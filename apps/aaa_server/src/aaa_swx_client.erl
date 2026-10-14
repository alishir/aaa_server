%%%-------------------------------------------------------------------
%%% @doc SWx Diameter client (AAA Server → HSS via DRA) and
%%% handler of HSS-initiated RTR / PPR callbacks.
%%%
%%% Application-ID 16777265, Vendor 10415 (3GPP TS 29.273 clause 8).
%%%
%%% Correct AVP semantics (fixes for the previous stub):
%%%   * MAR carries SIP-Authentication-Scheme = "EAP-AKA'",
%%%     SIP-Authorization = Network Name (TS 24.302 §8.1.1.2),
%%%     SIP-Number-Auth-Items, 3GPP-AAA-Server-Name, RAT-Type = WLAN.
%%%   * MAA parser reads XRES from SIP-Authorization (code 610), not
%%%     SIP-Authentication-Info — the previous code was wrong.
%%%   * SAR Server-Assignment-Type follows TS 29.273 §8.1.2.2.1:
%%%       1 = REGISTRATION                 (SWm AAR registration)
%%%       5 = USER_DEREGISTRATION          (SWm STR / S6b STR)
%%%      12 = AAA_USER_DATA_REQUEST        (refresh)
%%%      13 = PGW_UPDATE                   (S6b AAR registration)
%%%
%%% RTR (Registration-Termination-Request) from HSS is turned into a
%%% SWm ASR toward the ePDG cached in the session record. PPR pushes
%%% Non-3GPP-User-Data/APN-Configuration and triggers a SWm RAR.
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_swx_client).

-include_lib("diameter/include/diameter.hrl").
-include("aaa_session.hrl").

%% Public API: build/send SWx requests
-export([multimedia_auth_request/4,
         server_assignment_request/4]).

%% Diameter application callbacks
-export([peer_up/3, peer_down/3, pick_peer/4,
         prepare_request/3, prepare_retransmit/3,
         handle_answer/4, handle_error/4, handle_request/3]).

-define(SVC,        aaa_svc).
-define(APP_ALIAS,  swx).
-define(SWX_APP_ID, 16777265).
-define(VENDOR_3GPP, 10415).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Send MAR to HSS for EAP-AKA' authentication vectors.
%%
%% Per TS 29.273 §8.1.2.1, SIP-Auth-Data-Item MUST contain
%% SIP-Authentication-Scheme = "EAP-AKA'" and SIP-Authorization set
%% to the Access Network Identity (Network Name) so the HSS can
%% return CK'/IK' already bound to this access network.
-spec multimedia_auth_request(IMSI :: binary(),
                              NetworkName :: binary(),
                              NumVectors :: pos_integer(),
                              Opts :: map()) ->
    {ok, map()} | {error, term()}.
multimedia_auth_request(IMSI, NetworkName, NumVectors, Opts) ->
    OriginHost  = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OriginRealm = to_bin(aaa_config:get(origin_realm, "localdomain")),
    DestRealm   = to_bin(maps:get(destination_realm, Opts, OriginRealm)),
    SessionId   = session_id(<<"swx-mar">>),
    %% TS 29.273 §8.1.2.1.1: User-Name in SWx carries the EAP NAI
    %% (e.g. "6<IMSI>@nai.epc.mncXXX.mccXXX.3gppnetwork.org" for
    %% EAP-AKA' permanent identity per RFC 5448 §4.1.1.6). Fall back
    %% to the bare IMSI only if the caller did not supply a NAI.
    UserName = to_bin(maps:get(user_name, Opts, IMSI)),
    %% SIP-Authentication-Scheme selection per TS 29.273 §8.1.2.1.1:
    %% "EAP-AKA'" (RFC 5448) when the peer declared an EAP-AKA' NAI
    %% (leading "6"/"7"/"8"), "EAP-AKA" (RFC 4187) when it declared a
    %% plain EAP-AKA NAI (leading "0"/"2"/"4"). PyHSS supports both
    %% schemes; for plain EAP-AKA it returns raw CK/IK and the AAA
    %% derives the key schedule itself via RFC 4187 §7.
    AuthScheme = to_bin(maps:get(auth_scheme, Opts, <<"EAP-AKA'">>)),
    %% TS 29.273 §8.2.2.1.1: SIP-Auth-Data-Item carries the authentication
    %% scheme plus (on resync) SIP-Authorization=RAND||AUTS. It MUST NOT
    %% contain the Network Name — that belongs in the top-level
    %% ANID AVP (1504). The older behaviour of
    %% putting NetworkName in SIP-Authorization caused PyHSS (and any
    %% spec-conformant HSS) to mis-interpret the MAR as an SQN-resync
    %% trigger and feed Milenage a 4-byte "WLAN" blob where RAND||AUTS
    %% (46 bytes) was expected, producing the "XOR Error — S1 and S2
    %% don't match" Milenage complaint.
    AuthItem =
        [{'SIP-Authentication-Scheme', AuthScheme},
         {'SIP-Item-Number', 0}]
        ++ case maps:get(auts, Opts, undefined) of
            undefined -> [];
            Auts when is_binary(Auts) ->
                %% TS 29.273 §8.2.2.1: Resync-Info = RAND || AUTS.
                Rand = maps:get(rand, Opts, <<>>),
                [{'SIP-Authorization', <<Rand/binary, Auts/binary>>}]
        end,
    %% ANID (AVP 1504, TS 29.273 §5.2.3.7) is REQUIRED by TS 33.402
    %% §6.2 / RFC 5448 §3.3 for the HSS to derive CK'/IK' bound to the
    %% access network — but ONLY for EAP-AKA'. Plain EAP-AKA (RFC 4187)
    %% has no access-network binding, and PyHSS rejects the MAR with
    %% DIAMETER_MISSING_AVP (5005)/Unsupported-Scheme if ANID is
    %% supplied alongside SIP-Authentication-Scheme="EAP-AKA".
    BaseMsg = ['MAR',
           {'Session-Id', SessionId},
           {'Vendor-Specific-Application-Id',
                [{'Vendor-Id', ?VENDOR_3GPP},
                 {'Auth-Application-Id', ?SWX_APP_ID}]},
           {'Auth-Session-State', 1},                  % NO_STATE_MAINTAINED
           {'Origin-Host', OriginHost},
           {'Origin-Realm', OriginRealm},
           {'Destination-Realm', DestRealm},
           {'User-Name', UserName},
           {'SIP-Number-Auth-Items', NumVectors},
           {'SIP-Auth-Data-Item', [AuthItem]},
           {'3GPP-AAA-Server-Name', OriginHost},
           {'RAT-Type', maps:get(rat_type, Opts, 0)}   % 0 = WLAN
          ],
    Msg = case AuthScheme of
        <<"EAP-AKA'">> -> BaseMsg ++ [{'ANID', NetworkName}];
        _              -> BaseMsg
    end,
    call_and_parse(Msg, fun parse_maa/1, swx_mar_total).

%% @doc Send SAR to HSS.
%% AssignmentType per TS 29.273 §8.1.2.2.1.
-spec server_assignment_request(IMSI :: binary(),
                                AssignmentType :: 1..14,
                                APN :: binary() | undefined,
                                Opts :: map()) ->
    {ok, map()} | {error, term()}.
server_assignment_request(IMSI, AssignmentType, APN, Opts) ->
    OriginHost  = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OriginRealm = to_bin(aaa_config:get(origin_realm, "localdomain")),
    DestRealm   = to_bin(maps:get(destination_realm, Opts, OriginRealm)),
    SessionId   = session_id(<<"swx-sar">>),
    %% TS 29.273 §8.1.2.2.1: SWx SAR User-Name is the same NAI used in
    %% MAR so the HSS can key the registration on the permanent identity.
    UserName = to_bin(maps:get(user_name, Opts, IMSI)),
    Base = [
        'SAR',
        {'Session-Id', SessionId},
        {'Vendor-Specific-Application-Id',
            [{'Vendor-Id', ?VENDOR_3GPP},
             {'Auth-Application-Id', ?SWX_APP_ID}]},
        {'Auth-Session-State', 1},
        {'Origin-Host', OriginHost},
        {'Origin-Realm', OriginRealm},
        {'Destination-Realm', DestRealm},
        {'User-Name', UserName},
        {'Server-Assignment-Type', AssignmentType},
        {'3GPP-AAA-Server-Name', OriginHost}
    ],
    Msg1 = case APN of
        undefined -> Base;
        _         -> Base ++ [{'Service-Selection', APN}]
    end,
    Msg2 = case maps:get(rat_type, Opts, undefined) of
        undefined -> Msg1;
        R         -> Msg1 ++ [{'RAT-Type', R}]
    end,
    call_and_parse(Msg2, fun parse_saa/1, swx_sar_total).

%%====================================================================
%% Diameter callbacks (SWx application on the shared service)
%%====================================================================

peer_up(_Svc, {PeerRef, Caps}, State) ->
    RH = origin_host_cap(Caps),
    logger:notice("SWx peer up: ~s", [RH]),
    aaa_metrics:gauge_inc(swx_peers),
    %% The service keeps the last event per DRA host; see the
    %% post-peer-down grace handling in aaa_diameter_svc (KI-40).
    catch aaa_diameter_svc ! {diameter_peer_up, PeerRef},
    State.

peer_down(_Svc, {PeerRef, Caps}, State) ->
    RH = origin_host_cap(Caps),
    logger:warning("SWx peer down: ~s", [RH]),
    aaa_metrics:gauge_dec(swx_peers),
    %% Notify the service gen_server so it can schedule a DNS re-resolve
    %% and (if needed) rebuild the transport. OTP diameter's built-in
    %% reconnect loop reuses the literal `raddr' tuple we passed to
    %% add_transport, so if the DRA pod's IP changed, we will loop
    %% forever on the stale IP unless we explicitly remove + re-add the
    %% transport with a freshly-resolved address.
    catch aaa_diameter_svc ! {diameter_peer_down, PeerRef},
    State.

pick_peer([P | _], _, _Svc, _State) -> {ok, P};
pick_peer([], _, _Svc, _State)      -> false.

prepare_request(#diameter_packet{msg = Msg} = Pkt, _Svc, {_, Caps}) ->
    #diameter_caps{origin_host = {OH, _}, origin_realm = {OR, _}} = Caps,
    NewMsg = inject_origin(Msg, OH, OR),
    {send, Pkt#diameter_packet{msg = NewMsg}}.

prepare_retransmit(Pkt, Svc, Peer) ->
    prepare_request(Pkt, Svc, Peer).

handle_answer(#diameter_packet{msg = Msg}, _Req, _Svc, _Peer) ->
    {ok, Msg}.

handle_error(Reason, _Req, _Svc, _Peer) ->
    {error, Reason}.

%% Incoming RTR / PPR from HSS.
handle_request(#diameter_packet{msg = Msg}, _Svc, {_PeerRef, Caps}) ->
    try
        dispatch_incoming(Msg, Caps)
    catch Class:Reason:Stack ->
        logger:error("SWx handle_request crash ~p:~p ~p",
                     [Class, Reason, Stack]),
        {answer_message, 5012}
    end.

%%====================================================================
%% Incoming RTR / PPR
%%====================================================================

dispatch_incoming(['RTR' | AVPs], Caps) ->
    IMSI = avp('User-Name', AVPs, <<>>),
    ReasonCode = rtr_reason_code(AVPs),
    logger:notice("SWx RTR received for IMSI=~s reason=~p",
                  [IMSI, ReasonCode]),
    aaa_metrics:inc(swx_rtr_total),
    %% Propagate toward ePDG / PGW.
    Sessions = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    Ifaces = [S#aaa_session.interface || S <- Sessions],
    lists:foreach(fun detach_session/1, Sessions),
    case lists:member(swm, Ifaces) of
        true -> ok;
        false ->
            %% No cached SWm session: still emit ASR keyed by IMSI so
            %% the ePDG can look the UE up locally (TS 29.273 §7.1.2.4).
            aaa_swm_server:emit_abort_for_imsi(IMSI)
    end,
    aaa_session_mgr:remove_sessions_for_imsi(IMSI),
    rta_response(AVPs, Caps);

dispatch_incoming(['PPR' | AVPs], Caps) ->
    IMSI = avp('User-Name', AVPs, <<>>),
    logger:info("SWx PPR received for IMSI=~s", [IMSI]),
    aaa_metrics:inc(swx_ppr_total),
    %% Update cached subscription data and propagate a RAR.
    Non3gpp = avp('Non-3GPP-User-Data', AVPs, undefined),
    lists:foreach(fun(S) -> push_profile(S, Non3gpp) end,
                  aaa_session_mgr:get_sessions_for_imsi(IMSI)),
    ppa_response(AVPs, Caps);

dispatch_incoming(_Other, _Caps) ->
    {answer_message, 3001}.   % DIAMETER_COMMAND_UNSUPPORTED

detach_session(#aaa_session{interface = swm} = S) ->
    aaa_swm_server:emit_abort_session(S);
detach_session(#aaa_session{interface = sta} = S) ->
    aaa_sta_server:emit_abort_session(S);
detach_session(#aaa_session{interface = s6b} = S) ->
    aaa_s6b_server:emit_abort_session(S);
detach_session(_) ->
    ok.

push_profile(#aaa_session{interface = swm, session_id = Sid} = S, Non3gpp) ->
    aaa_session_mgr:update_session(Sid, #{non_3gpp_user_data => Non3gpp}),
    aaa_swm_server:emit_reauth(S);
push_profile(#aaa_session{interface = s6b, session_id = Sid} = S, Non3gpp) ->
    aaa_session_mgr:update_session(Sid, #{non_3gpp_user_data => Non3gpp}),
    aaa_s6b_server:emit_reauth(S);
push_profile(#aaa_session{interface = sta, session_id = Sid} = S, Non3gpp) ->
    aaa_session_mgr:update_session(Sid, #{non_3gpp_user_data => Non3gpp}),
    aaa_sta_server:emit_reauth(S);
push_profile(_, _) -> ok.

rta_response(AVPs, _Caps) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    Sid = avp('Session-Id', AVPs, <<>>),
    {reply, ['RTA',
             {'Session-Id', Sid},
             {'Vendor-Specific-Application-Id',
                [{'Vendor-Id', ?VENDOR_3GPP},
                 {'Auth-Application-Id', ?SWX_APP_ID}]},
             {'Auth-Session-State', 1},
             {'Origin-Host', OH},
             {'Origin-Realm', OR},
             {'Result-Code', 2001}]}.

ppa_response(AVPs, _Caps) ->
    OH = to_bin(aaa_config:get(origin_host, "aaa.localdomain")),
    OR = to_bin(aaa_config:get(origin_realm, "localdomain")),
    Sid = avp('Session-Id', AVPs, <<>>),
    {reply, ['PPA',
             {'Session-Id', Sid},
             {'Vendor-Specific-Application-Id',
                [{'Vendor-Id', ?VENDOR_3GPP},
                 {'Auth-Application-Id', ?SWX_APP_ID}]},
             {'Auth-Session-State', 1},
             {'Origin-Host', OH},
             {'Origin-Realm', OR},
             {'Result-Code', 2001}]}.

%%====================================================================
%% MAA / SAA parsers
%%====================================================================

%% @private
%% Correct AVP mapping per TS 29.273 §8.2.2.1:
%%   SIP-Authenticate  (609) = RAND || AUTN (32 bytes)
%%   SIP-Authorization (610) = XRES          (8–16 bytes)
%%   Confidentiality-Key (625) = CK'         (16 bytes)
%%   Integrity-Key       (626) = IK'         (16 bytes)
parse_maa(['MAA' | AVPs]) ->
    ResultCode = result_code(AVPs),
    case ResultCode of
        2001 ->
            Items = all_avps('SIP-Auth-Data-Item', AVPs),
            Vectors = [parse_auth_item(I) || I <- Items],
            {ok, #{result_code => 2001,
                   auth_vectors => [V || V <- Vectors, V =/= undefined]}};
        Code ->
            {error, {diameter_error, Code}}
    end;
parse_maa(_) ->
    {error, invalid_answer}.

%% With `{decode_format, list}` a Grouped AVP's value is delivered as
%% [SubAVPs]; `proplists:get_all_values/2` therefore returns
%% [[SubAVPs]] for a single occurrence. Strip that single-element
%% wrapper before treating the payload as the sub-AVP proplist, otherwise
%% every `avp/3` lookup would miss and return empty binaries (observed
%% as rand=<<>>, ik=<<>>, ck=<<>> which crashed aaa_eap_crypto:derive_keys/3).
parse_auth_item([Item]) when is_list(Item) ->
    parse_auth_item(Item);
parse_auth_item(Item) when is_list(Item) ->
    SipAuth = avp('SIP-Authenticate', Item, <<>>),
    SipAuz  = avp('SIP-Authorization', Item, <<>>),
    CK      = avp('Confidentiality-Key', Item, <<>>),
    IK      = avp('Integrity-Key', Item, <<>>),
    {Rand, Autn} = split_auth(SipAuth),
    #{rand => Rand,
      autn => Autn,
      xres => SipAuz,          % XRES in SIP-Authorization per TS 29.273
      ck   => CK,
      ik   => IK};
parse_auth_item(_) -> undefined.

%% SIP-Authenticate = RAND (16) || AUTN (16).
split_auth(<<Rand:16/binary, Autn:16/binary, _/binary>>) ->
    {Rand, Autn};
split_auth(<<Rand:16/binary>>) ->
    {Rand, <<>>};
split_auth(_) ->
    {<<>>, <<>>}.

parse_saa(['SAA' | AVPs]) ->
    case result_code(AVPs) of
        2001 ->
            UserData = proplists:get_value('Non-3GPP-User-Data', AVPs, []),
            APNs     = extract_apns(UserData),
            {ok, #{result_code => 2001,
                   non_3gpp_user_data => UserData,
                   apn_configurations => APNs}};
        Code ->
            {error, {diameter_error, Code}}
    end;
parse_saa(_) ->
    {error, invalid_answer}.

%% Erlang's diameter decoder delivers AVP 1500 (Non-3GPP-User-Data) as
%% [GroupedProplist] because its arity in SAA is `[0..1]`. So UserData
%% is typically `[[{'APN-Configuration', ListOfApnProplists}, ...]]` —
%% a one-element list wrapping the inner grouped proplist. Older code
%% iterated the outer list looking for `{'APN-Configuration', _}` tuples
%% at the top, which never matched and silently returned [].
extract_apns([Inner | _]) when is_list(Inner) ->
    APNs0 = proplists:get_value('APN-Configuration', Inner, []),
    case APNs0 of
        [] ->
            case proplists:get_value('APN-Configuration-Profile', Inner, undefined) of
                [Profile | _] when is_list(Profile) ->
                    proplists:get_value('APN-Configuration', Profile, []);
                Profile when is_list(Profile) ->
                    proplists:get_value('APN-Configuration', Profile, []);
                _ ->
                    []
            end;
        _ ->
            APNs0
    end;
extract_apns(UserData) when is_list(UserData) ->
    [APN || {'APN-Configuration', APN} <- UserData];
extract_apns(_) ->
    [].

%%====================================================================
%% Helpers
%%====================================================================

call_and_parse(Msg, Parser, Metric) ->
    aaa_metrics:inc(Metric),
    Start = erlang:monotonic_time(millisecond),
    Raw = diameter:call(?SVC, ?APP_ALIAS, Msg, []),
    Ret = case Raw of
        {ok, Answer}    -> Parser(Answer);
        Ans when is_list(Ans) -> Parser(Ans);
        {error, R}      ->
            aaa_metrics:inc(swx_errors_total),
            {error, R};
        Other           ->
            aaa_metrics:inc(swx_errors_total),
            {error, Other}
    end,
    aaa_metrics:observe_latency(swx_latency,
        erlang:monotonic_time(millisecond) - Start),
    Ret.

inject_origin(Msg, OH, OR) when is_list(Msg) ->
    %% Replace or prepend Origin-Host / Origin-Realm.
    Stripped = [AVP || AVP <- Msg,
                       not is_origin(AVP)],
    Cmd = hd(Stripped),
    [Cmd,
     {'Origin-Host', OH},
     {'Origin-Realm', OR}
     | tl(Stripped)].

is_origin({'Origin-Host', _})  -> true;
is_origin({'Origin-Realm', _}) -> true;
is_origin(_)                   -> false.

session_id(Suffix) ->
    Host = to_bin(aaa_config:get(origin_host, "aaa")),
    T    = erlang:system_time(microsecond),
    <<Host/binary, ";", (integer_to_binary(T))/binary, ";", Suffix/binary>>.

origin_host_cap(#diameter_caps{origin_host = {_, H}}) -> H;
origin_host_cap(_) -> <<"unknown">>.

%% With `decode_format=list' optional AVPs arrive as [Value] — unwrap.
avp(Key, List, Default) ->
    case proplists:get_value(Key, List, Default) of
        [V]   -> V;
        Other -> Other
    end.
all_avps(Key, List)     -> proplists:get_all_values(Key, List).

result_code(AVPs) ->
    case avp('Result-Code', AVPs, undefined) of
        undefined ->
            case avp('Experimental-Result', AVPs, undefined) of
                [{'Vendor-Id', _}, {'Experimental-Result-Code', RC}] ->
                    unwrap_int(RC);
                [{'Experimental-Result-Code', RC}, {'Vendor-Id', _}] ->
                    unwrap_int(RC);
                #{'Experimental-Result-Code' := RC} ->
                    unwrap_int(RC);
                _ -> 0
            end;
        RC -> unwrap_int(RC)
    end.

unwrap_int([I]) when is_integer(I) -> I;
unwrap_int(I) when is_integer(I)   -> I;
unwrap_int(_) -> 0.

rtr_reason_code(AVPs) ->
    case proplists:get_value('Deregistration-Reason', AVPs) of
        List when is_list(List) ->
            proplists:get_value('Reason-Code', List, undefined);
        _ -> undefined
    end.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L);
to_bin(A) when is_atom(A)   -> atom_to_binary(A, utf8);
to_bin(I) when is_integer(I)-> integer_to_binary(I).
