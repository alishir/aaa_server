%%%-------------------------------------------------------------------
%%% @doc Unified Diameter service — owns the single Diameter service
%%% instance that advertises all four 3GPP auth applications
%%% (SWm / SWx / S6b / STa) on a single CER/CEA peer exchange.
%%%
%%% Per TS 29.273, a DRA / HSS peer may relay traffic for multiple
%%% applications (SWx + S6b, say) across one transport connection, so
%%% the base Diameter service must advertise every Auth-Application-Id
%%% that we support on a given peer.
%%%
%%% Transports:
%%%   * SWm listener  (port AAA_SWM_PORT) — ePDG connects
%%%   * STa listener  (port AAA_STA_PORT) — trusted WLAN AN connects
%%%   * S6b listener  (port AAA_S6B_PORT) — PGW connects
%%%   * SWx connect   (to each DRA_HOSTS, port DRA_PORT) — AAA ↔ HSS
%%%
%%% Each listener configures its `capabilities` such that only the
%%% relevant Auth-Application-Id is advertised on the corresponding
%%% transport, while the service itself carries all applications.
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_diameter_svc).

-behaviour(gen_server).

-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").

-export([start_link/0,
         service_name/0,
         swx_peer_count/0,
         listener_status/0,
         trigger_reconnect_all/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
%% Pure decision rule, exported for the test suite.
-export([reconnect_decision/3]).

-define(SVC,        aaa_svc).
-define(VENDOR_3GPP, 10415).

-define(SWM_APP_ID, 16777264).
-define(SWX_APP_ID, 16777265).
-define(S6B_APP_ID, 16777272).
-define(STA_APP_ID, 16777250).

-define(FIRMWARE_REVISION, 11).

-define(HEALTH_INTERVAL, 30000).

-record(state, {
    started :: boolean(),
    origin_host :: binary(),
    origin_realm :: binary(),
    listeners = #{} :: #{atom() => term()},
    sta_enabled :: boolean(),
    dra_hosts = [] :: [string()],
    dra_port :: non_neg_integer() | undefined,
    dra_transport_mod :: module() | undefined,
    swx_transports = #{} :: #{string() => {term() | undefined, non_neg_integer()}},
    %% Last peer_up / peer_down seen per DRA host (unknown until the first
    %% event). Read when the post-peer-down grace period ends.
    peer_state = #{} :: #{string() => up | down}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec service_name() -> atom().
service_name() -> ?SVC.

-spec swx_peer_count() -> non_neg_integer().
swx_peer_count() ->
    case catch diameter:service_info(?SVC, connections) of
        Conns when is_list(Conns) ->
            length([C || C <- Conns]);
        _ -> 0
    end.

-spec listener_status() -> #{atom() => ok | down}.
listener_status() ->
    gen_server:call(?MODULE, listener_status, 5000).

-spec trigger_reconnect_all() -> ok.
trigger_reconnect_all() ->
    gen_server:cast(?MODULE, reconnect_all).

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    diameter:start(),
    %% Ensure the generated codec modules are loaded before diameter
    %% tries to resolve the application dictionary.
    lists:foreach(fun code:ensure_loaded/1,
        [diameter_gen_swm, diameter_gen_swx,
         diameter_gen_s6b, diameter_gen_sta]),

    OriginHost  = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OriginRealm = to_bin(aaa_config:get(origin_realm, "localdomain")),
    StaEnabled  = aaa_config:get(sta_enabled, false),

    SvcOpts = service_options(OriginHost, OriginRealm, StaEnabled),
    case diameter:start_service(?SVC, SvcOpts) of
        ok ->
            S0 = #state{started = true,
                        origin_host = OriginHost,
                        origin_realm = OriginRealm,
                        sta_enabled = StaEnabled},
            S1 = start_listeners(S0),
            S2 = start_swx_transports(S1),
            erlang:send_after(?HEALTH_INTERVAL, self(), health_check),
            {ok, S2};
        {error, Reason} ->
            logger:error("Failed to start Diameter service ~p: ~p",
                         [?SVC, Reason]),
            {ok, #state{started = false,
                        origin_host = OriginHost,
                        origin_realm = OriginRealm,
                        sta_enabled = StaEnabled}}
    end.

handle_call(listener_status, _From, #state{listeners = L} = State) ->
    {reply, L, State};
handle_call(_Req, _From, State) -> {reply, ok, State}.

handle_cast(reconnect_all, State) ->
    NewState = lists:foldl(fun(H, S) -> try_connect_swx(H, S) end,
                           State, State#state.dra_hosts),
    {noreply, NewState};
handle_cast(_Msg, State) -> {noreply, State}.

handle_info({retry_swx, Host}, State) ->
    {noreply, try_connect_swx(Host, State)};
handle_info({diameter_peer_up, PeerRef},
            #state{swx_transports = Ts, peer_state = PS} = State) ->
    case host_for_peer_ref(PeerRef, Ts) of
        undefined -> {noreply, State};
        Host      -> {noreply, State#state{peer_state = PS#{Host => up}}}
    end;
handle_info({diameter_peer_down, PeerRef},
            #state{swx_transports = Ts, peer_state = PS} = State) ->
    %% A DRA peer dropped. Map the PeerRef back to one of our outbound
    %% SWx transports (if any) and schedule a DNS re-resolution + rebuild.
    %% If the PeerRef belongs to an inbound listener (e.g. ePDG on SWm,
    %% PGW on S6b), it will not match any entry in swx_transports and we
    %% simply ignore the event — listener peers have no host to re-resolve.
    case host_for_peer_ref(PeerRef, Ts) of
        undefined ->
            {noreply, State};
        Host ->
            logger:notice(
              "[dra-reconnect] SWx peer down for ~s — scheduling DNS "
              "re-resolve in 15s", [Host]),
            erlang:send_after(15000, self(), {re_resolve_dra, Host}),
            {noreply, State#state{peer_state = PS#{Host => down}}}
    end;
handle_info({re_resolve_dra, Host},
            #state{swx_transports = Ts, peer_state = PS} = State) ->
    case maps:find(Host, Ts) of
        {ok, {OldRef, _}} when OldRef =/= undefined ->
            %% OTP's own connect timer (5 s) usually has the connection
            %% back long before this grace period ends. Rebuilding the
            %% transport then was a second, self-inflicted outage per peer
            %% drop, on the connection that also carries the DRA's SWm and
            %% S6b requests to this AAA (KI-40). Rebuild only when the peer
            %% is still down or its address changed.
            TInfos = transport_infos(),
            case reconnect_decision(maps:get(Host, PS, unknown),
                                    raddr_for_ref(OldRef, TInfos),
                                    resolve_host(Host)) of
                keep ->
                    logger:notice(
                      "[dra-reconnect] DRA ~s recovered on its own, "
                      "keeping the transport", [Host]),
                    {noreply, State};
                rebuild ->
                    logger:notice(
                      "[dra-reconnect] re-resolving DRA ~s after peer down",
                      [Host]),
                    aaa_metrics:inc(dra_transport_rebuilds_total),
                    catch diameter:remove_transport(?SVC, OldRef),
                    NewTs = Ts#{Host => {undefined, 0}},
                    {noreply, try_connect_swx(Host,
                                              State#state{swx_transports = NewTs})}
            end;
        _ ->
            %% No ref (transport never came up, or was already torn down);
            %% still attempt a connect so we recover from DNS failure too.
            {noreply, try_connect_swx(Host, State)}
    end;
handle_info({force_reconnect, Host},
            #state{swx_transports = Ts} = State) ->
    case maps:find(Host, Ts) of
        {ok, {OldRef, _}} when OldRef =/= undefined ->
            logger:warning(
              "[dra-reconnect] forcing SWx reconnect to DRA ~s "
              "(stale IP detected)", [Host]),
            aaa_metrics:inc(dra_transport_rebuilds_total),
            catch diameter:remove_transport(?SVC, OldRef),
            NewTs = Ts#{Host => {undefined, 0}},
            {noreply, try_connect_swx(Host, State#state{swx_transports = NewTs})};
        _ ->
            {noreply, try_connect_swx(Host, State)}
    end;
handle_info(health_check, State) ->
    aaa_metrics:gauge_set(swx_peers, swx_peer_count()),
    %% Detect stale IPs: if DNS for a configured DRA host now resolves to
    %% a different address than the one our transport was opened with,
    %% force a rebuild. Required because OTP diameter's reconnect loop
    %% never re-consults DNS on its own.
    check_stale_dra_ips(State),
    erlang:send_after(?HEALTH_INTERVAL, self(), health_check),
    {noreply, State};
handle_info(_, State) -> {noreply, State}.

terminate(_Reason, #state{started = true}) ->
    diameter:stop_service(?SVC), ok;
terminate(_, _) -> ok.

code_change(_, S, _) -> {ok, S}.

%%====================================================================
%% Service / listeners / transports
%%====================================================================

service_options(OH, OR, StaEnabled) ->
    AuthIds = [?SWM_APP_ID, ?SWX_APP_ID, ?S6B_APP_ID]
        ++ case StaEnabled of true -> [?STA_APP_ID]; _ -> [] end,
    OriginStateId = erlang:system_time(second),
    [{'Origin-Host',  OH},
     {'Origin-Realm', OR},
     {'Vendor-Id', ?VENDOR_3GPP},
     {'Product-Name', "volte.io AAA Server"},
     {'Origin-State-Id', OriginStateId},
     {'Firmware-Revision', ?FIRMWARE_REVISION},
     {'Auth-Application-Id', AuthIds},
     {'Supported-Vendor-Id', [?VENDOR_3GPP]},
     {'Vendor-Specific-Application-Id',
        [#'diameter_base_Vendor-Specific-Application-Id'{
            'Vendor-Id' = ?VENDOR_3GPP,
            'Auth-Application-Id' = [Id]} || Id <- AuthIds]},
     {string_decode, false},
     %% All application handler modules (aaa_swm_server, aaa_swx_client,
     %% aaa_s6b_server, aaa_sta_server) pattern-match the list form
     %% `['Cmd' | AVPs]` on incoming requests. OTP's default
     %% `decode_format' is `record', which delivers messages as
     %% `#diameter_swm_DER{}' records and would make every handler fall
     %% through its catch-all clause (answering 3001).
     {decode_format, list},
     {application, [{alias, swm},
                    {dictionary, diameter_gen_swm},
                    {module, aaa_swm_server},
                    {answer_errors, callback},
                    %% Deliberately use `callback' so decode/routing 3xxx
                    %% errors reach handle_request and we can see WHY
                    %% OTP would have auto-answered 3001.
                    {request_errors, callback}]},
     {application, [{alias, swx},
                    {dictionary, diameter_gen_swx},
                    {module, aaa_swx_client},
                    {answer_errors, callback},
                    {request_errors, answer_3xxx}]},
     {application, [{alias, s6b},
                    {dictionary, diameter_gen_s6b},
                    {module, aaa_s6b_server},
                    {answer_errors, callback},
                    {request_errors, answer_3xxx}]},
     {application, [{alias, sta},
                    {dictionary, diameter_gen_sta},
                    {module, aaa_sta_server},
                    {answer_errors, callback},
                    {request_errors, answer_3xxx}]}].

start_listeners(State) ->
    ListenerSpecs = [
        {swm, aaa_config:get(swm_port, 3868),  aaa_config:get(swm_transport, "tcp")},
        {s6b, aaa_config:get(s6b_port, 3869),  aaa_config:get(s6b_transport, "tcp")}
    ] ++ case State#state.sta_enabled of
        true  -> [{sta, aaa_config:get(sta_port, 3870),
                        aaa_config:get(sta_transport, "tcp")}];
        _     -> []
    end,
    lists:foldl(fun({Name, Port, TStr}, S) -> add_listener(Name, Port, TStr, S) end,
                State, ListenerSpecs).

add_listener(Name, Port, TStr, #state{listeners = L} = State) ->
    TMod = transport_module(TStr),
    Result = diameter:add_transport(?SVC, {listen, [
        {transport_module, TMod},
        {transport_config, [{reuseaddr, true},
                            {ip, {0,0,0,0}},
                            {port, Port}] ++ socket_opts(TMod)}
    ]}),
    case Result of
        {ok, Ref} ->
            logger:notice("~s listener up on port ~B (~s)", [Name, Port, TStr]),
            State#state{listeners = L#{Name => Ref}};
        {error, Err} ->
            logger:error("~s listener failed on port ~B: ~p",
                         [Name, Port, Err]),
            State#state{listeners = L#{Name => {error, Err}}}
    end.

start_swx_transports(State) ->
    Hosts = aaa_config:get(dra_hosts, ["dra-diameter"]),
    Port  = aaa_config:get(dra_port, 3868),
    TStr  = aaa_config:get(dra_transport, "tcp"),
    TMod  = transport_module(TStr),
    Initial = maps:from_list([{H, {undefined, 0}} || H <- Hosts]),
    State1 = State#state{dra_hosts = Hosts,
                         dra_port = Port,
                         dra_transport_mod = TMod,
                         swx_transports = Initial},
    logger:notice("SWx: connecting to ~B DRA host(s): ~p",
                  [length(Hosts), Hosts]),
    lists:foldl(fun(H, S) -> try_connect_swx(H, S) end, State1, Hosts).

try_connect_swx(Host, #state{dra_port = Port, dra_transport_mod = TMod,
                             swx_transports = Ts} = State) ->
    {_OldRef, Retries} = maps:get(Host, Ts, {undefined, 0}),
    case resolve_host(Host) of
        {ok, IP} ->
            case diameter:add_transport(?SVC, {connect, [
                {transport_module, TMod},
                {transport_config, [{raddr, IP}, {rport, Port},
                                    {ip, {0,0,0,0}}] ++ socket_opts(TMod)},
                {reconnect_timer, 5000},
                %% Advertise ALL AAA-served apps on this transport.
                %% The DRA reuses this TCP connection to relay SWm DERs
                %% (ePDG → DRA → AAA). If we advertise SWx only, OTP
                %% diameter auto-rejects the incoming SWm DER with 3001
                %% before any application handler sees it.
                {capabilities,
                    [{'Auth-Application-Id',
                        [?SWM_APP_ID, ?SWX_APP_ID, ?S6B_APP_ID]},
                     {'Vendor-Specific-Application-Id',
                        [#'diameter_base_Vendor-Specific-Application-Id'{
                            'Vendor-Id' = ?VENDOR_3GPP,
                            'Auth-Application-Id' = [Id]}
                         || Id <- [?SWM_APP_ID, ?SWX_APP_ID, ?S6B_APP_ID]]}]}
            ]}) of
                {ok, Ref} ->
                    logger:notice("SWx transport added -> DRA ~s:~B", [Host, Port]),
                    State#state{swx_transports = Ts#{Host => {Ref, 0}}};
                {error, Err} ->
                    logger:error("SWx transport to DRA ~s:~B failed: ~p",
                                 [Host, Port, Err]),
                    Delay = retry_delay(Retries),
                    erlang:send_after(Delay, self(), {retry_swx, Host}),
                    State#state{swx_transports =
                        Ts#{Host => {undefined, Retries + 1}}}
            end;
        {error, Rsn} ->
            Delay = retry_delay(Retries),
            logger:warning("DNS fail for DRA ~s: ~p, retry in ~Bms",
                           [Host, Rsn, Delay]),
            erlang:send_after(Delay, self(), {retry_swx, Host}),
            State#state{swx_transports = Ts#{Host => {undefined, Retries + 1}}}
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% gen_sctp opens its sockets with a 1024 byte receive buffer. The AAA
%% server then advertised a receive window of about 1.3 kB to the DRA, less
%% than one SWx answer with user data, and the DRA's send queue towards it
%% filled up under load until SWx requests timed out. Nagle is off per
%% RFC 3539 section 3.2. The kernel caps recbuf at net.core.rmem_max.
socket_opts(diameter_sctp) -> [{sctp_nodelay, true}, {recbuf, 262144}];
socket_opts(_)             -> [].

transport_module("sctp") -> diameter_sctp;
transport_module("tcp")  -> diameter_tcp;
transport_module(_)      -> diameter_tcp.

retry_delay(R) -> min(5000 bsl min(R, 4), 60000).

resolve_host(H) ->
    case inet:getaddr(H, inet) of
        {ok, IP} -> {ok, IP};
        {error, _} ->
            case inet:getaddr(list_to_atom(H), inet) of
                {ok, IP} -> {ok, IP};
                E -> E
            end
    end.

%% Map a diameter PeerRef back to the DRA hostname we opened a SWx
%% connect transport to. Returns `undefined' if the PeerRef belongs to
%% something other than one of our outbound SWx transports (e.g. an
%% inbound listener peer).
host_for_peer_ref(PeerRef, Transports) ->
    TInfos = case catch diameter:service_info(?SVC, transport) of
                 L when is_list(L) -> L;
                 _ -> []
             end,
    case find_transport_ref(TInfos, PeerRef) of
        {ok, TransRef} ->
            case [H || {H, {R, _}} <- maps:to_list(Transports),
                       R =:= TransRef] of
                [Host | _] -> Host;
                [] -> undefined
            end;
        error -> undefined
    end.

find_transport_ref(TInfos, PeerRef) ->
    Matches = [proplists:get_value(ref, Info)
               || Info <- TInfos,
                  is_list(Info),
                  match_peer_ref(Info, PeerRef)],
    case Matches of
        [Ref | _] -> {ok, Ref};
        [] -> error
    end.

match_peer_ref(Info, PeerRef) ->
    case proplists:get_value(peer, Info) of
        {_, PRef} when PRef =:= PeerRef -> true;
        _ ->
            case proplists:get_value(accept, Info) of
                Accept when is_list(Accept) ->
                    lists:any(fun(A) ->
                        case proplists:get_value(peer, A) of
                            {_, PR} when PR =:= PeerRef -> true;
                            _ -> false
                        end
                    end, Accept);
                _ -> false
            end
    end.

%% Whether a DRA transport is rebuilt (removed and added again with a
%% fresh DNS answer) or kept. `PeerUp' is the last peer event seen for
%% the host, `RAddr' the address the transport was opened with, `Dns' the
%% current lookup result. Keep only when the peer is up and nothing
%% changed; an unknown peer state rebuilds, so the rule never degrades
%% to "no reconnect".
-spec reconnect_decision(up | down | unknown,
                         inet:ip_address() | undefined,
                         {ok, inet:ip_address()} | {error, term()}) ->
          keep | rebuild.
reconnect_decision(up, RAddr, {ok, RAddr}) when RAddr =/= undefined -> keep;
reconnect_decision(up, RAddr, {error, _}) when RAddr =/= undefined  -> keep;
reconnect_decision(_PeerUp, _RAddr, _Dns)                           -> rebuild.

transport_infos() ->
    case catch diameter:service_info(?SVC, transport) of
        L when is_list(L) -> L;
        _ -> []
    end.

%% For every configured DRA host, compare the current transport's
%% `raddr' against a fresh DNS lookup. If they differ, queue a
%% force_reconnect so the transport is rebuilt against the new IP.
check_stale_dra_ips(#state{dra_hosts = Hosts, swx_transports = Ts}) ->
    TInfos = transport_infos(),
    lists:foreach(
      fun(Host) ->
          case maps:get(Host, Ts, undefined) of
              {Ref, _} when Ref =/= undefined ->
                  maybe_force_reconnect(Host, Ref, TInfos);
              _ -> ok
          end
      end, Hosts).

maybe_force_reconnect(Host, Ref, TInfos) ->
    case raddr_for_ref(Ref, TInfos) of
        undefined -> ok;
        RAddr ->
            Dns = resolve_host(Host),
            %% The health check only acts on an address change; whether
            %% the peer is up is left to the peer-down path. Hence `up'.
            case reconnect_decision(up, RAddr, Dns) of
                rebuild ->
                    {ok, CurrentIP} = Dns,
                    logger:warning(
                      "[dra-reconnect] stale IP detected for ~s: "
                      "transport raddr=~p, current DNS=~p — "
                      "forcing reconnect",
                      [Host, RAddr, CurrentIP]),
                    self() ! {force_reconnect, Host};
                keep -> ok
            end
    end.

raddr_for_ref(Ref, TInfos) ->
    case [proplists:get_value(transport_config,
            proplists:get_value(options, Info, []), [])
          || Info <- TInfos,
             is_list(Info),
             proplists:get_value(ref, Info) =:= Ref] of
        [Cfg | _] -> proplists:get_value(raddr, Cfg);
        [] -> undefined
    end.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L).
