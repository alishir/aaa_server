%%%-------------------------------------------------------------------
%%% @doc SWm Diameter application — terminates requests from the ePDG.
%%%
%%% Application-ID 16777264, Vendor 10415 (3GPP TS 29.273 clause 7).
%%%
%%% The module is a pure `diameter' application callback (no gen_server)
%%% registered on the shared service owned by `aaa_diameter_svc'. It
%%% dispatches on the actual Diameter command code — not on
%%% Auth-Request-Type — so STR/ASR/RAR are also routed, and emits
%%% server-initiated ASR/RAR toward the ePDG when the HSS drives a
%%% user deregistration or profile update (TS 29.273 §7.1.2.4).
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_swm_server).

-include_lib("diameter/include/diameter.hrl").
-include("aaa_session.hrl").

%% Diameter application callbacks
-export([peer_up/3, peer_down/3, pick_peer/4,
         prepare_request/3, prepare_retransmit/3,
         handle_answer/4, handle_error/4, handle_request/3]).

%% Server-initiated requests (called by SWx RTR/PPR handler)
-export([emit_abort_session/1, emit_reauth/1, emit_abort_for_imsi/1]).

-define(SVC,        aaa_svc).
-define(APP_ALIAS,  swm).
-define(SWM_APP_ID, 16777264).
-define(VENDOR_3GPP, 10415).

%%====================================================================
%% Diameter peer lifecycle
%%====================================================================

peer_up(_Svc, {_PeerRef, Caps}, State) ->
    logger:notice("SWm peer up: ~s (ePDG connected)", [origin_host(Caps)]),
    aaa_metrics:gauge_inc(swm_peers),
    State.

peer_down(_Svc, {_PeerRef, Caps}, State) ->
    logger:notice("SWm peer down: ~s", [origin_host(Caps)]),
    aaa_metrics:gauge_dec(swm_peers),
    State.

pick_peer([P | _], _, _, _) -> {ok, P};
pick_peer([], _, _, _)       -> false.

prepare_request(#diameter_packet{msg = Msg} = Pkt, _Svc, {_, Caps}) ->
    {send, Pkt#diameter_packet{msg = inject_origin(Msg, Caps)}}.

prepare_retransmit(Pkt, Svc, Peer) ->
    prepare_request(Pkt, Svc, Peer).

handle_answer(#diameter_packet{msg = Msg}, _Req, _Svc, _Peer) ->
    {ok, Msg}.

handle_error(Reason, _Req, _Svc, _Peer) ->
    {error, Reason}.

%% Incoming request dispatcher.
handle_request(#diameter_packet{msg = Msg, header = Hdr} = _Pkt, _Svc,
               {_PeerRef, Caps}) ->
    Start = erlang:monotonic_time(millisecond),
    aaa_metrics:inc(swm_requests_total),
    try
        Reply = dispatch(Msg, Hdr, Caps),
        aaa_metrics:observe_latency(swm_latency,
            erlang:monotonic_time(millisecond) - Start),
        Reply
    catch Class:R:St ->
        logger:error("SWm handle_request crash ~p:~p ~p", [Class, R, St]),
        {answer_message, 5012}
    end.

%%====================================================================
%% Command dispatch (per Diameter command code, not Auth-Request-Type)
%%====================================================================

%% DER (Diameter-EAP-Request, code 268)
dispatch(['DER' | AVPs], _Hdr, Caps) ->
    handle_der(AVPs, Caps);
dispatch(['AAR' | AVPs], _Hdr, Caps) ->
    handle_aar(AVPs, Caps);
dispatch(['STR' | AVPs], _Hdr, Caps) ->
    handle_str(AVPs, Caps);
dispatch(['ASA' | _], _Hdr, _Caps) ->
    %% Answer to server-initiated ASR — just drop.
    discard;
dispatch(['RAA' | _], _Hdr, _Caps) ->
    discard;
dispatch(_Other, _Hdr, _Caps) ->
    {answer_message, 3001}.  % DIAMETER_COMMAND_UNSUPPORTED

%%====================================================================
%% DER — EAP relay
%%====================================================================

handle_der(AVPs, Caps) ->
    SessionId  = avp('Session-Id', AVPs, <<>>),
    EapPayload = avp('EAP-Payload', AVPs, <<>>),
    PeerHost   = origin_host(Caps),
    %% TS 29.273 §9.2.3.1.1: the ePDG carries the UE's outer (local) IP
    %% on SWu in the DER. Record it on the session so it is queryable by
    %% IMSI from the core (e.g. the HSS-GUI ePDG Sessions view).
    UELocalIP  = fmt_ue_ip(avp('UE-Local-IP-Address', AVPs, undefined)),

    EpdgHost = avp('Origin-Host', AVPs, PeerHost),
    note_epdg_host(EpdgHost),
    case load_or_create_session_tagged(SessionId, AVPs, EpdgHost) of
        {error, Reason} ->
            %% No session record, no authentication: the store is full
            %% or unreachable. DIAMETER_UNABLE_TO_COMPLY instead of a
            %% crash per request.
            logger:error("SWm DER sid=~s: cannot store session: ~p",
                         [SessionId, Reason]),
            aaa_metrics:inc(swm_auth_failure_total),
            {reply, dea_failure(SessionId, <<>>, 5012)};
        {Session0, _SessionSource} ->
            handle_der_authenticated(SessionId, EapPayload, UELocalIP, Session0)
    end.

handle_der_authenticated(SessionId, EapPayload, UELocalIP, Session0) ->
    Result = aaa_eap_relay:process(swm, EapPayload, Session0),
    case Result of
        {challenge, ResponseEAP, Updates} ->
            aaa_session_mgr:update_session(SessionId,
                merge_ue_ip(Updates, UELocalIP)),
            {reply, dea_multi_round(SessionId, ResponseEAP)};
        {success, ResponseEAP, MSK, Updates} ->
            aaa_metrics:inc(swm_auth_success_total),
            aaa_session_mgr:update_session(SessionId,
                merge_ue_ip(Updates, UELocalIP)),
            %% This session is now the UE's SWm session; the ones of an
            %% earlier attach of the same IMSI are gone (TS 29.273
            %% clause 7: one SWm session per UE at the 3GPP AAA Server).
            case aaa_session_mgr:supersede_sessions(
                   swm, Session0#aaa_session.imsi, SessionId, undefined) of
                []  -> ok;
                Old -> logger:notice("SWm session superseded IMSI=~s new=~s old=~p",
                                     [Session0#aaa_session.imsi, SessionId, Old])
            end,
            %% Issue SAR already-done inside aaa_eap_relay; fetch cached
            %% subscription to include in the DEA authorization half.
            {reply, dea_success(SessionId, ResponseEAP, MSK, Session0)};
        {failure, ResponseEAP, _Why} ->
            aaa_metrics:inc(swm_auth_failure_total),
            {reply, dea_failure(SessionId, ResponseEAP, 4181)};
        {notification, ResponseEAP} ->
            {reply, dea_multi_round(SessionId, ResponseEAP)};
        {error, _Reason} ->
            aaa_metrics:inc(swm_auth_failure_total),
            {reply, dea_failure(SessionId, <<>>, 4181)}
    end.

%%====================================================================
%% AAR — authorization
%%====================================================================

handle_aar(AVPs, Caps) ->
    SessionId = avp('Session-Id', AVPs, <<>>),
    IMSI      = avp('User-Name', AVPs, <<>>),
    AuthReqType = avp('Auth-Request-Type', AVPs, 1),
    PeerHost  = avp('Origin-Host', AVPs, origin_host(Caps)),
    APN       = avp('Service-Selection', AVPs, undefined),

    %% Ensure session exists with proper binding (IMSI ↔ SessionId).
    _ = load_or_create_session(SessionId, AVPs, PeerHost),
    aaa_session_mgr:update_session(SessionId,
        #{imsi => IMSI, apn => APN, origin_host => PeerHost,
          interface => swm}),

    AssignmentType = case AuthReqType of
        1 -> 1;    % AUTHORIZE_ONLY          → REGISTRATION
        2 -> 12;   % AUTHORIZE_AUTHENTICATE  → AAA_USER_DATA_REQUEST (refresh)
        3 -> 1;    % AUTHENTICATE_ONLY       → REGISTRATION
        _ -> 1
    end,
    case aaa_swx_client:server_assignment_request(IMSI, AssignmentType, APN, #{}) of
        {ok, #{non_3gpp_user_data := UserData, apn_configurations := APNs}} ->
            aaa_session_mgr:update_session(SessionId,
                #{non_3gpp_user_data => UserData,
                  apn_configuration => APNs}),
            {reply, aaa_success(SessionId, IMSI, AuthReqType, UserData, APNs)};
        {error, _R} ->
            {reply, aaa_failure(SessionId, IMSI, AuthReqType, 5012)}
    end.

%%====================================================================
%% STR — session termination
%%====================================================================

%% Grace before an S6b session left behind by a SWm STR is removed: the
%% PGW's own S6b STR, triggered by the ePDG's S2b Delete, normally arrives
%% within this time.
-define(S6B_ORPHAN_GRACE_MS, 60000).

str_followup(sar_deregistration, IMSI) ->
    _ = aaa_swx_client:server_assignment_request(IMSI, 5, undefined, #{}),
    ok;
str_followup({s6b_grace, #aaa_session{session_id = Sid}}, IMSI) ->
    spawn(fun() ->
        timer:sleep(?S6B_ORPHAN_GRACE_MS),
        case aaa_session_mgr:end_session(s6b, Sid) of
            {ok, _, Followup} ->
                logger:notice("S6b session ~s of IMSI=~s orphaned after the SWm "
                              "STR, removed", [Sid, IMSI]),
                aaa_metrics:inc(sessions_orphaned_total),
                lists:foreach(fun(F) -> str_followup(F, IMSI) end, Followup);
            error ->
                ok
        end
    end),
    ok;
str_followup(_, _IMSI) ->
    ok.

handle_str(AVPs, _Caps) ->
    SessionId = avp('Session-Id', AVPs, <<>>),
    case aaa_session_mgr:end_session(swm, SessionId) of
        {ok, #aaa_session{imsi = IMSI}, Followup} when is_binary(IMSI) ->
            lists:foreach(fun(F) -> str_followup(F, IMSI) end, Followup);
        _ ->
            ok
    end,
    {reply, sta_response(SessionId, 2001)}.

%%====================================================================
%% Server-initiated ASR / RAR toward ePDG (triggered by SWx RTR/PPR)
%%====================================================================

-spec emit_abort_session(#aaa_session{}) -> ok.
emit_abort_session(#aaa_session{session_id = Sid, origin_host = PeerHost,
                                origin_realm = PeerRealm, imsi = IMSI}) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    DestRealm = case PeerRealm of
        undefined -> OR;
        V -> V
    end,
    DestHost = case PeerHost of
        undefined -> OH;
        H -> H
    end,
    Msg = ['ASR',
           {'Session-Id', Sid},
           {'Origin-Host', OH},
           {'Origin-Realm', OR},
           {'Destination-Realm', DestRealm},
           {'Destination-Host', DestHost},
           {'Auth-Application-Id', ?SWM_APP_ID},
           {'User-Name', IMSI},
           {'Auth-Session-State', 1}],
    %% Dest-Host is the ePDG; AAA's only SWm peers are the DRAs.
    %% Default filter {all,[host,realm]} therefore fails. Send by realm
    %% so DRA receives the request and relays on Destination-Host
    %% (RFC 6733 §6.1.5; DRA ≥ 0.7.53).
    CallRet = diameter:call(?SVC, ?APP_ALIAS, Msg, [{filter, realm}, detach]),
    case CallRet of
        ok ->
            logger:notice("SWm ASR sent IMSI=~s dest_host=~s", [IMSI, DestHost]);
        _ ->
            logger:warning("SWm ASR send failed IMSI=~s dest_host=~s ret=~p",
                           [IMSI, DestHost, CallRet])
    end,
    aaa_metrics:inc(swm_asr_total),
    ok.

%% @doc HSS RTR with no cached SWm session: fan ASR toward every known
%% ePDG Origin-Host (from other live SWm sessions) so the serving ePDG
%% can look the UE up by IMSI.
-spec emit_abort_for_imsi(binary() | list()) -> ok.
emit_abort_for_imsi(IMSI0) ->
    IMSI = case IMSI0 of
        B when is_binary(B) -> B;
        [H] when is_binary(H) -> H;
        L when is_list(L) -> list_to_binary(L);
        _ -> <<>>
    end,
    case IMSI of
        <<>> -> ok;
        _ ->
            Hosts = lists:usort(unique_swm_dest_hosts() ++ configured_epdg_hosts()),
            case Hosts of
                [] ->
                    logger:notice("SWm ASR skipped for IMSI=~s: no ePDG Destination-Host "
                                  "(set AAA_SWM_EPDG_DESTINATION_HOSTS)", [IMSI]);
                _ ->
                    lists:foreach(
                      fun(Host) ->
                          emit_abort_session(#aaa_session{
                              session_id = <<(to_bin(aaa_config:get(origin_host, <<"aaa">>)))/binary,
                                             ";rtr;", IMSI/binary>>,
                              origin_host = Host,
                              origin_realm = to_bin(aaa_config:get(origin_realm, "localdomain")),
                              imsi = IMSI
                          })
                      end, Hosts)
            end,
            ok
    end.

%% The ePDG hosts seen on SWm. Kept in a small Redis set written at every
%% DER instead of reading every SWm session for one RTR (KI-46: that was
%% an MGET of all sessions per RTR without a cached session).
unique_swm_dest_hosts() ->
    case aaa_redis:smembers(aaa_redis:key([<<"epdg_hosts">>])) of
        {ok, Hosts} when is_list(Hosts) -> lists:usort([H || H <- Hosts, is_binary(H), H =/= <<>>]);
        _ -> []
    end.

%% Remember an ePDG host for emit_abort_for_imsi/1; refreshed on every DER,
%% expires a day after the last one.
note_epdg_host(Host) when is_binary(Host), Host =/= <<>> ->
    Key = aaa_redis:key([<<"epdg_hosts">>]),
    _ = aaa_redis:multi([[<<"SADD">>, Key, Host], [<<"EXPIRE">>, Key, <<"86400">>]]),
    ok;
note_epdg_host(_) -> ok.

configured_epdg_hosts() ->
    case aaa_config:get(swm_epdg_destination_hosts, []) of
        L when is_list(L) ->
            [to_bin(H) || H <- L, H =/= "", H =/= <<>>];
        B when is_binary(B), B =/= <<>> ->
            [to_bin(H) || H <- string:split(binary_to_list(B), ",", all),
                          string:trim(H) =/= ""];
        _ -> []
    end.

-spec emit_reauth(#aaa_session{}) -> ok.
emit_reauth(#aaa_session{session_id = Sid, origin_host = PeerHost,
                         origin_realm = PeerRealm, imsi = IMSI}) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    DestRealm = case PeerRealm of
        undefined -> OR;
        V -> V
    end,
    DestHost = case PeerHost of
        undefined -> OH;
        H -> H
    end,
    Msg = ['RAR',
           {'Session-Id', Sid},
           {'Origin-Host', OH},
           {'Origin-Realm', OR},
           {'Destination-Realm', DestRealm},
           {'Destination-Host', DestHost},
           {'Auth-Application-Id', ?SWM_APP_ID},
           {'Re-Auth-Request-Type', 0},   % AUTHORIZE_ONLY
           {'User-Name', IMSI},
           {'Auth-Session-State', 1}],
    _ = diameter:call(?SVC, ?APP_ALIAS, Msg, [{filter, realm}, detach]),
    aaa_metrics:inc(swm_rar_total),
    ok.

%%====================================================================
%% Message builders
%%====================================================================

dea_multi_round(Sid, EapPayload) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    ['DEA',
     {'Session-Id', Sid},
     {'Auth-Application-Id', ?SWM_APP_ID},
     {'Result-Code', 1001},                % DIAMETER_MULTI_ROUND_AUTH
     {'Origin-Host', OH},
     {'Origin-Realm', OR},
     {'Auth-Request-Type', 3},             % AUTHORIZE_AUTHENTICATE
     {'EAP-Payload', EapPayload}].

dea_success(Sid, EapPayload, MSK,
            #aaa_session{non_3gpp_user_data = UserData,
                         apn_configuration = APNs,
                         imsi = IMSI}) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    Base = ['DEA',
            {'Session-Id', Sid},
            {'Auth-Application-Id', ?SWM_APP_ID},
            {'Result-Code', 2001},
            {'Origin-Host', OH},
            {'Origin-Realm', OR},
            {'Auth-Request-Type', 3},
            {'EAP-Payload', EapPayload},
            {'EAP-Master-Session-Key', MSK},
            {'Session-Timeout', session_established_timeout()},
            {'Auth-Grace-Period', 60},
            {'MIP6-Feature-Vector', mip6_feature_vector()},
            {'3GPP-AAA-Server-Name', OH}],
    with_subscription(Base, IMSI, UserData, APNs).

dea_failure(Sid, EapPayload, ResultCode) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    Base = ['DEA',
            {'Session-Id', Sid},
            {'Auth-Application-Id', ?SWM_APP_ID},
            {'Result-Code', ResultCode},
            {'Origin-Host', OH},
            {'Origin-Realm', OR},
            {'Auth-Request-Type', 3}],
    case EapPayload of
        <<>> -> Base;
        _    -> Base ++ [{'EAP-Payload', EapPayload}]
    end.

aaa_success(Sid, IMSI, AuthReqType, UserData, APNs) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    Base = ['AAA',
            {'Session-Id', Sid},
            {'Auth-Application-Id', ?SWM_APP_ID},
            {'Result-Code', 2001},
            {'Origin-Host', OH},
            {'Origin-Realm', OR},
            {'Auth-Request-Type', AuthReqType},
            {'User-Name', IMSI},
            {'Session-Timeout', session_established_timeout()},
            {'MIP6-Feature-Vector', mip6_feature_vector()},
            {'3GPP-AAA-Server-Name', OH}],
    with_subscription(Base, IMSI, UserData, APNs).

aaa_failure(Sid, IMSI, AuthReqType, ResultCode) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    ['AAA',
     {'Session-Id', Sid},
     {'Auth-Application-Id', ?SWM_APP_ID},
     {'Result-Code', ResultCode},
     {'Origin-Host', OH},
     {'Origin-Realm', OR},
     {'Auth-Request-Type', AuthReqType},
     {'User-Name', IMSI}].

sta_response(Sid, ResultCode) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    ['STA',
     {'Session-Id', Sid},
     {'Result-Code', ResultCode},
     {'Origin-Host', OH},
     {'Origin-Realm', OR}].

with_subscription(Msg, _IMSI, undefined, _) -> Msg;
with_subscription(Msg, _IMSI, UserData, APNs) ->
    Ext = case UserData of
        undefined -> [];
        UD        -> [{'Non-3GPP-User-Data', UD}]
    end,
    ApnExt = case APNs of
        [] -> [];
        _  -> [{'APN-Configuration', APNs}]
    end,
    Msg ++ Ext ++ ApnExt.

%%====================================================================
%% Session management
%%====================================================================

load_or_create_session(SessionId, AVPs, PeerHost) ->
    {S, _Src} = load_or_create_session_tagged(SessionId, AVPs, PeerHost),
    S.

load_or_create_session_tagged(SessionId, AVPs, PeerHost) ->
    case aaa_session_mgr:get_session(SessionId) of
        {ok, S} ->
            {S, existing};
        error ->
            IMSI = avp('User-Name', AVPs, undefined),
            Rec = #aaa_session{
                session_id = SessionId,
                imsi = IMSI,
                interface = swm,
                origin_host = PeerHost,
                origin_realm = avp('Origin-Realm', AVPs, undefined),
                apn = avp('Service-Selection', AVPs, undefined),
                rat_type = avp('RAT-Type', AVPs, 0),
                visited_plmn = avp('Visited-Network-Identifier', AVPs, undefined),
                ue_local_ip = fmt_ue_ip(avp('UE-Local-IP-Address', AVPs, undefined)),
                created_ts = 0, updated_ts = 0},
            case aaa_session_mgr:create_session(Rec) of
                ok             -> {Rec, created};
                {error, _} = E -> E
            end
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% The generated SWm dictionary declares User-Name, EAP-Payload, etc.
%% as `[AVP]` (0..1). With `decode_format=list`, OTP delivers these as a
%% one-element list `[Value]` when present. Unwrap to hand callers the
%% scalar value they expect (and match the `Default' shape).
avp(Key, List, Default) ->
    case proplists:get_value(Key, List, Default) of
        [V]   -> V;
        Other -> Other
    end.

origin_host(#diameter_caps{origin_host = {_, H}}) -> H;
origin_host(_) -> <<"unknown">>.

%% Normalise the decoded UE-Local-IP-Address (an inet:ip_address()
%% tuple under decode_format=list) to a printable binary for storage
%% and JSON display. Returns `undefined' when the AVP was absent.
fmt_ue_ip(IP) when is_tuple(IP) -> list_to_binary(inet:ntoa(IP));
fmt_ue_ip(_)                    -> undefined.

merge_ue_ip(Updates, undefined) -> Updates;
merge_ue_ip(Updates, IP)        -> Updates#{ue_local_ip => IP}.

inject_origin(Msg, Caps) when is_list(Msg) ->
    #diameter_caps{origin_host = {OH, _}, origin_realm = {OR, _}} = Caps,
    Stripped = [AVP || AVP <- Msg,
                       not is_origin(AVP)],
    Cmd = hd(Stripped),
    [Cmd, {'Origin-Host', OH}, {'Origin-Realm', OR} | tl(Stripped)].

is_origin({'Origin-Host', _})  -> true;
is_origin({'Origin-Realm', _}) -> true;
is_origin(_)                   -> false.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L).

session_timeout() ->
    %% In-progress EAP / Diameter default.
    aaa_config:get(session_timeout, 3600).

session_established_timeout() ->
    case aaa_config:get(session_established_timeout, undefined) of
        N when is_integer(N), N > 0 -> N;
        _ -> session_timeout()
    end.

%% MIP6-Feature-Vector bits (RFC 5447 §4.1):
%%   0x00000001 = MIP6_INTEGRATED
%%   0x00010000 = PMIP6_SUPPORTED
%%   0x00020000 = GTPv2_BASED
%%   0x00040000 = ASSIGN_HOME_LINK_LOCAL_PREFIX_IN_IPV4_HOA
%% Default: PMIP6_SUPPORTED | GTPv2_BASED, suitable for ePDG→PGW over
%% GTPv2 as deployed today.
mip6_feature_vector() ->
    aaa_config:get(mip6_feature_vector, 16#00030000).
