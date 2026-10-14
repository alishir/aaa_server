%%%-------------------------------------------------------------------
%%% @doc AAA session state manager (Redis-backed).
%%%
%%% Keeps the IMSI ↔ Session-Id dual index required by TS 29.273 so
%%% that HSS-initiated RTR/PPR (SWx) can be correlated to the active
%%% ePDG/PGW Diameter sessions and propagated as SWm ASR/RAR toward
%%% the access gateway.
%%%
%%% Storage layout in Redis (prefix `aaa:' — configurable via
%%% AAA_REDIS_KEY_PREFIX):
%%%
%%%   * aaa:sess:&lt;SessionId&gt;    STRING   term_to_binary(#aaa_session{})
%%%   * aaa:imsi:&lt;IMSI&gt;         SET      of SessionIds for that IMSI
%%%   * aaa:nai:&lt;NAI&gt;           STRING   permanent IMSI bound to NAI
%%%   * aaa:iface:&lt;swm|sta|s6b&gt; SET      of SessionIds on that interface
%%%
%%% All writes that touch multiple keys are wrapped in MULTI/EXEC to
%%% keep the indexes consistent. TTL is set on the session blob from
%%% `expiry_ts' (or the configured default) and re-armed on every
%%% update; the cleanup loop scrubs stale SET members whose session
%%% key has already expired.
%%%
%%% A running gen_server process is retained only so the cleanup
%%% timer and the readiness probe have a well-known pid to target
%%% (existing callers `whereis(aaa_session_mgr)' and
%%% `gen_server:stop/1' keep working).
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_session_mgr).

-behaviour(gen_server).

-include("aaa_session.hrl").

-export([start_link/0,
         create_session/1, update_session/2, get_session/1,
         get_sessions_for_imsi/1, indexed_sessions_for_imsi/1,
         sessions_by_interface/1,
         remove_session/1, remove_sessions_for_imsi/1,
         supersede_sessions/4,
         str_followup/2, end_session/2,
         bind_nai/2, resolve_nai/1,
         count/0, count/1,
         list_all/0,
         %% The periodic clean-up, callable from the test suite.
         run_cleanup/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(CLEANUP_INTERVAL_MS, 60 * 1000).
-define(DEFAULT_TTL_SEC, 3600).
%% Established SWm/S6b sessions outlive the 1h EAP default so an
%% HSS RTR hours later can still find the ePDG Origin-Host (TS 29.273).
-define(ESTABLISHED_TTL_SEC, 604800).

%% Cap on how long the IMSI / NAI / iface index SETs are allowed to
%% live without being refreshed. Individual sessions carry their own
%% TTL; the index TTL is a safety-net so orphaned sets don't pile up.
-define(INDEX_TTL_MARGIN_SEC, 600).

%% The clean-up reads every session blob of an interface. In chunks, so
%% one reply stays small, and under a lock so only one AAA pod per
%% minute does it (KI-46: one MGET of all sessions per pod and minute).
-define(PRUNE_CHUNK, 500).
-define(PRUNE_LOCK_TTL_SEC, 55).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Create a fresh session record. The caller fills in imsi,
%% session_id, interface, and any available fields.
-spec create_session(#aaa_session{}) -> ok | {error, term()}.
create_session(#aaa_session{session_id = SessionId,
                            imsi       = IMSI0,
                            interface  = Iface} = S0) ->
    IMSI = normalize_identity(IMSI0),
    Now  = erlang:system_time(second),
    S1   = S0#aaa_session{imsi = IMSI, created_ts = Now, updated_ts = Now},
    Ttl  = ttl_for(S1),
    Blob = term_to_binary(S1, [{compressed, 3}]),

    SKey = sess_key(SessionId),
    ICmds = iface_cmds(Iface, SessionId, Ttl),
    MCmds = imsi_cmds(IMSI, SessionId, Ttl),

    case aaa_redis:multi([ [<<"SETEX">>, SKey, integer_to_binary(Ttl), Blob]
                           | ICmds ++ MCmds ]) of
        {ok, _} ->
            aaa_metrics:inc(sessions_created_total),
            ok;
        {error, <<"OOM", _/binary>> = Reason} ->
            %% Redis is at `maxmemory' with `noeviction': the store is
            %% full. Reported separately so the capacity alarm is not
            %% mistaken for a connection problem.
            aaa_metrics:inc(redis_oom_errors_total),
            logger:error("aaa_session_mgr:create_session: session store full "
                         "sid=~s: ~s", [SessionId, Reason]),
            {error, redis_oom};
        {error, Reason} = E ->
            logger:warning("aaa_session_mgr:create_session failed sid=~s reason=~p",
                           [SessionId, Reason]),
            E
    end.

%% @doc Partial update. Updates is a map of field_name => value.
-spec update_session(binary(), map()) -> ok | {error, not_found | term()}.
update_session(SessionId, Updates) when is_map(Updates) ->
    case get_session(SessionId) of
        {ok, S0} ->
            Now = erlang:system_time(second),
            S1  = apply_updates(S0, Updates),
            S2  = S1#aaa_session{updated_ts = Now},
            Ttl = ttl_for(S2),
            Blob = term_to_binary(S2, [{compressed, 3}]),
            SKey = sess_key(SessionId),
            ExtraCmds =
                %% Re-arm IMSI/iface index TTLs on every update so they
                %% cannot expire while the session blob is still live.
                case S2#aaa_session.imsi of
                    undefined -> [];
                    NewI -> imsi_cmds(NewI, SessionId, Ttl)
                end ++
                case S2#aaa_session.interface of
                    undefined -> [];
                    Iface -> iface_cmds(Iface, SessionId, Ttl)
                end,
            case aaa_redis:multi([
                    [<<"SETEX">>, SKey, integer_to_binary(Ttl), Blob]
                    | ExtraCmds ]) of
                {ok, _} -> ok;
                {error, _} = E -> E
            end;
        error ->
            {error, not_found}
    end.

-spec get_session(binary()) -> {ok, #aaa_session{}} | error.
get_session(SessionId) ->
    case aaa_redis:get(sess_key(SessionId)) of
        {ok, undefined} -> error;
        {ok, Bin} when is_binary(Bin) ->
            try
                {ok, binary_to_term(Bin, [safe])}
            catch
                _:_ -> error
            end;
        {error, Reason} ->
            logger:warning("aaa_session_mgr:get_session redis error sid=~s reason=~p",
                           [SessionId, Reason]),
            error
    end.

-spec get_sessions_for_imsi(binary() | list()) -> [#aaa_session{}].
get_sessions_for_imsi(IMSI0) ->
    case normalize_identity(IMSI0) of
        undefined -> [];
        IMSI ->
            Keys = imsi_aliases(IMSI),
            Ids = lists:usort(lists:append([smembers_ids(K) || K <- Keys])),
            Sessions = mget_sessions(Ids),
            case Sessions of
                [] -> filter_all_by_imsi(IMSI);
                _  -> Sessions
            end
    end.

%% @doc Like get_sessions_for_imsi/1 but from the index only, without
%% the keyspace scan fallback. For the hot path (a new attach of an IMSI
%% that has no session is the common case, and must not scan).
-spec indexed_sessions_for_imsi(binary() | list()) -> [#aaa_session{}].
indexed_sessions_for_imsi(IMSI0) ->
    case normalize_identity(IMSI0) of
        undefined -> [];
        IMSI ->
            Ids = lists:usort(lists:append([smembers_ids(K) || K <- imsi_aliases(IMSI)])),
            mget_sessions(Ids)
    end.

%% @doc What the AAA does after a session on `Iface' ended, given the
%% sessions of the IMSI that remain (TS 29.273 clauses 7, 8 and 9):
%%
%%   * `sar_deregistration': no session on any interface is left, so the
%%     HSS is told that the user left non-3GPP access (SWx SAR type 5).
%%     Up to 0.1.25 every SWm or S6b STR sent that SAR at once, while the
%%     other interface still held the user's session (KI-46).
%%   * `{swm_asr, S}': the S6b session ended (the PGW released the PDN
%%     connection) while the SWm session S remains: the ePDG is told to
%%     end the tunnel (clause 7.2.2.3). Deferred a few seconds, because a
%%     normal detach makes the PGW's S6b STR and the ePDG's SWm STR race.
%%   * `{s6b_grace, S}': the SWm session ended while the S6b session S
%%     remains. No S6b ASR: the ePDG's S2b Delete makes the PGW send its
%%     own STR. If S is still there after the grace period it is removed.
%%
%% Pure, so the rule is testable without Diameter.
-spec str_followup(swm | sta | s6b, [#aaa_session{}]) ->
          [sar_deregistration | {swm_asr, #aaa_session{}} | {s6b_grace, #aaa_session{}}].
str_followup(_Iface, []) ->
    [sar_deregistration];
str_followup(Iface, Remaining) ->
    [{swm_asr, S} || Iface =:= s6b,
                     #aaa_session{interface = swm} = S <- Remaining] ++
    [{s6b_grace, S} || Iface =/= s6b,
                       #aaa_session{interface = s6b} = S <- Remaining].

%% @doc Remove the session `Sid' of `Iface' and return what has to follow
%% (see str_followup/2). `error' when the session is unknown.
-spec end_session(swm | sta | s6b, binary()) ->
          {ok, #aaa_session{}, [term()]} | error.
end_session(Iface, Sid) ->
    case get_session(Sid) of
        {ok, #aaa_session{imsi = IMSI} = S} ->
            remove_loaded(S),
            Remaining = [R || R <- indexed_sessions_for_imsi(IMSI),
                              R#aaa_session.session_id =/= Sid],
            {ok, S, str_followup(Iface, Remaining)};
        error ->
            error
    end.

%% @doc A new session replaces the older sessions of the same IMSI on the
%% same interface (TS 29.273: the 3GPP AAA Server keeps one SWm session
%% per UE and one S6b session per PDN connection). On S6b only sessions
%% of the same APN are replaced, a UE may hold several PDN connections.
%% Without this every re-attach left its predecessors in the store for
%% the established-session lifetime (KI-46). Returns the removed ids.
-spec supersede_sessions(swm | sta | s6b, binary() | list() | undefined,
                         binary(), binary() | undefined) -> [binary()].
supersede_sessions(_Iface, undefined, _NewSid, _APN) -> [];
supersede_sessions(Iface, IMSI, NewSid, APN) ->
    Old = [S || #aaa_session{session_id = Sid, interface = I} = S
                    <- indexed_sessions_for_imsi(IMSI),
                I =:= Iface, Sid =/= NewSid,
                Iface =/= s6b orelse S#aaa_session.apn =:= APN],
    lists:foreach(fun remove_loaded/1, Old),
    case Old of
        [] -> ok;
        _  -> aaa_metrics:inc(sessions_superseded_total, length(Old))
    end,
    [S#aaa_session.session_id || S <- Old].

-spec sessions_by_interface(swm | sta | s6b) -> [#aaa_session{}].
sessions_by_interface(Iface) ->
    case aaa_redis:smembers(iface_key(Iface)) of
        {ok, Ids} when is_list(Ids) ->
            mget_sessions(Ids);
        _ -> []
    end.

-spec remove_session(binary()) -> ok.
remove_session(SessionId) ->
    case get_session(SessionId) of
        {ok, S} ->
            remove_loaded(S);
        error ->
            _ = aaa_redis:del(sess_key(SessionId)),
            ok
    end.

%% Remove a session whose record is already loaded: the blob and its
%% entries in the IMSI alias sets and the interface set.
remove_loaded(#aaa_session{session_id = SessionId, imsi = IMSI,
                           interface = Iface}) ->
    %% NB: lists:append/1 (one-level flatten) — lists:flatten/1
    %% would dissolve each command list into its binaries and
    %% break the MULTI pipeline.
    Cmds = lists:append([
        [[<<"DEL">>, sess_key(SessionId)]],
        case IMSI of
            undefined -> [];
            _ ->
                [[<<"SREM">>, imsi_key(K), SessionId]
                 || K <- imsi_aliases(IMSI)]
        end,
        case Iface of
            undefined -> [];
            _ -> [[<<"SREM">>, iface_key(Iface), SessionId]]
        end
    ]),
    _ = aaa_redis:multi(Cmds),
    ok.

%% @doc Remove every session for an IMSI and return the list that was
%% removed (callers in `aaa_swx_client' use the list to emit SWm ASR
%% toward the ePDG / PGW).
-spec remove_sessions_for_imsi(binary()) -> [#aaa_session{}].
remove_sessions_for_imsi(IMSI) when is_binary(IMSI) ->
    Sessions = get_sessions_for_imsi(IMSI),
    DelKeys  = [sess_key(S#aaa_session.session_id) || S <- Sessions],
    Ifaces   = lists:usort([S#aaa_session.interface ||
                            S <- Sessions,
                            S#aaa_session.interface =/= undefined]),
    %% Remove per-interface set entries too. lists:append/1 flattens
    %% exactly one level so each command stays a list of binaries.
    Cmds = lists:append([
        case DelKeys of
            [] -> [];
            _  -> [[<<"DEL">> | DelKeys]]
        end,
        [[<<"DEL">>, imsi_key(K)] || K <- imsi_aliases(IMSI)],
        [[<<"SREM">>, iface_key(I)] ++ [S#aaa_session.session_id
                                          || S <- Sessions,
                                             S#aaa_session.interface =:= I]
         || I <- Ifaces, Sessions =/= []]
    ]),
    case Cmds of
        [] -> ok;
        _  -> _ = aaa_redis:multi(Cmds), ok
    end,
    Sessions;
remove_sessions_for_imsi(_) -> [].

%% @doc Bind a pseudonym / fast-reauth NAI to an IMSI so future
%% authentication attempts starting from that NAI can look up the
%% underlying permanent identity.
-spec bind_nai(binary(), binary()) -> ok.
bind_nai(NAI, IMSI) when is_binary(NAI), is_binary(IMSI) ->
    Ttl = default_ttl(),
    case aaa_redis:setex(nai_key(NAI), Ttl, IMSI) of
        ok             -> ok;
        {error, _} = E ->
            logger:warning("aaa_session_mgr:bind_nai redis error: ~p", [E]),
            ok
    end.

-spec resolve_nai(binary()) -> {ok, binary()} | error.
resolve_nai(NAI) when is_binary(NAI) ->
    case aaa_redis:get(nai_key(NAI)) of
        {ok, undefined}              -> error;
        {ok, IMSI} when is_binary(IMSI) -> {ok, IMSI};
        _                            -> error
    end;
resolve_nai(_) -> error.

-spec count() -> non_neg_integer().
count() ->
    count(swm) + count(sta) + count(s6b).

-spec count(swm | sta | s6b) -> non_neg_integer().
count(Iface) ->
    case aaa_redis:scard(iface_key(Iface)) of
        {ok, Bin} when is_binary(Bin) -> binary_to_integer(Bin);
        {ok, N} when is_integer(N)    -> N;
        _                             -> 0
    end.

%% @doc Full listing — intended for debugging and the HTTP /status
%% endpoint. SCANs through the session keyspace; not used on the hot
%% Diameter path.
-spec list_all() -> [#aaa_session{}].
list_all() ->
    Pattern = iolist_to_binary([aaa_redis:key_prefix(), <<"sess:*">>]),
    Ids = scan_keys(Pattern),
    [S || K <- Ids,
          Sid <- [strip_sess_prefix(K)],
          {ok, S} <- [get_session(Sid)]].

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    erlang:send_after(?CLEANUP_INTERVAL_MS, self(), cleanup),
    {ok, #{}}.

handle_call(_Req, _From, State) -> {reply, ok, State}.
handle_cast(_Msg, State)        -> {noreply, State}.

handle_info(cleanup, State) ->
    run_cleanup(),
    erlang:send_after(?CLEANUP_INTERVAL_MS, self(), cleanup),
    {noreply, State};
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%% @doc One clean-up pass: prune the interface sets (one pod per minute)
%% and refresh the session gauges (every pod).
-spec run_cleanup() -> ok.
run_cleanup() ->
    try
        case claim_prune_lock() of
            true  -> prune_interface_sets();
            false -> ok
        end
    catch
        Class:Reason:Stack ->
            logger:warning("aaa_session_mgr cleanup failed ~p:~p ~P",
                           [Class, Reason, Stack, 10])
    end,
    refresh_active_gauge(),
    ok.

%%====================================================================
%% Key helpers
%%====================================================================

sess_key(Sid)            -> aaa_redis:key([<<"sess:">>, Sid]).
imsi_key(IMSI)           -> aaa_redis:key([<<"imsi:">>, IMSI]).
nai_key(NAI)             -> aaa_redis:key([<<"nai:">>, NAI]).
iface_key(I) when is_atom(I) ->
    aaa_redis:key([<<"iface:">>, atom_to_binary(I, utf8)]).

strip_sess_prefix(K) when is_binary(K) ->
    Prefix = iolist_to_binary([aaa_redis:key_prefix(), <<"sess:">>]),
    PSize  = byte_size(Prefix),
    case K of
        <<Prefix:PSize/binary, Rest/binary>> -> Rest;
        _ -> K
    end.

%%====================================================================
%% Internal
%%====================================================================

ttl_for(#aaa_session{expiry_ts = T}) when is_integer(T), T > 0 ->
    Now = erlang:system_time(second),
    case T - Now of
        N when N > 0 -> N;
        _            -> default_ttl()
    end;
ttl_for(#aaa_session{eap_state = success}) ->
    established_ttl();
ttl_for(#aaa_session{interface = s6b}) ->
    established_ttl();
ttl_for(_) ->
    default_ttl().

default_ttl() ->
    case aaa_config:get(session_timeout, ?DEFAULT_TTL_SEC) of
        N when is_integer(N), N > 0 -> N;
        _                           -> ?DEFAULT_TTL_SEC
    end.

established_ttl() ->
    case aaa_config:get(session_established_timeout, ?ESTABLISHED_TTL_SEC) of
        N when is_integer(N), N > 0 -> N;
        _                           -> ?ESTABLISHED_TTL_SEC
    end.

imsi_cmds(undefined, _Sid, _Ttl) -> [];
imsi_cmds(IMSI, Sid, Ttl) ->
    lists:append([
        begin
            K = imsi_key(Key),
            [ [<<"SADD">>, K, Sid],
              [<<"EXPIRE">>, K, integer_to_binary(Ttl + ?INDEX_TTL_MARGIN_SEC)] ]
        end || Key <- imsi_aliases(IMSI)
    ]).

%% Diameter list-decode often hands User-Name as [<<"…">>] (0..1 AVP).
%% Collapse that to a binary before indexing or looking up.
normalize_identity(undefined) -> undefined;
normalize_identity(<<>>) -> undefined;
normalize_identity(B) when is_binary(B) -> B;
normalize_identity([H]) -> normalize_identity(H);
normalize_identity(L) when is_list(L) ->
    case io_lib:printable_unicode_list(L) orelse
         lists:all(fun(C) -> is_integer(C) andalso C >= 0 andalso C =< 255 end, L) of
        true  -> list_to_binary(L);
        false -> undefined
    end;
normalize_identity(_) -> undefined.

%% Index both the raw User-Name (often a NAI) and the bare IMSI so
%% HSS-initiated SWx RTR (bare IMSI) finds sessions stored from S6b
%% (permanent NAI) and SWm (bare IMSI or EAP NAI).
imsi_aliases(undefined) -> [];
imsi_aliases(IMSI0) ->
    case normalize_identity(IMSI0) of
        undefined -> [];
        IMSI ->
            User = strip_realm(IMSI),
            Canon = canonical_imsi(IMSI),
            lists:usort([IMSI, User, Canon])
    end.

strip_realm(IMSI) ->
    Bin = normalize_identity(IMSI),
    case Bin of
        undefined -> <<>>;
        _ ->
            case binary:split(Bin, <<"@">>) of
                [User, _] -> User;
                [User]    -> User
            end
    end.

canonical_imsi(IMSI0) ->
    User = strip_realm(IMSI0),
    case User of
        <<D, Rest/binary>> when (D =:= $0 orelse D =:= $6),
                                 byte_size(Rest) >= 14 ->
            Rest;
        _ ->
            User
    end.

smembers_ids(IMSI) ->
    case aaa_redis:smembers(imsi_key(IMSI)) of
        {ok, Ids} when is_list(Ids) -> Ids;
        _ -> []
    end.

filter_all_by_imsi(IMSI) ->
    Bare = canonical_imsi(IMSI),
    [S || S <- list_all(),
          S#aaa_session.imsi =/= undefined,
          canonical_imsi(S#aaa_session.imsi) =:= Bare].

iface_cmds(undefined, _Sid, _Ttl) -> [];
iface_cmds(Iface, Sid, Ttl) ->
    K = iface_key(Iface),
    [ [<<"SADD">>, K, Sid],
      [<<"EXPIRE">>, K, integer_to_binary(Ttl + ?INDEX_TTL_MARGIN_SEC)] ].

apply_updates(S, Updates) ->
    maps:fold(fun set_field/3, S, Updates).

set_field(Key, Val, S) ->
    case field_index(Key) of
        undefined -> S;
        Ix        -> setelement(Ix, S, Val)
    end.

field_index(session_id)          -> #aaa_session.session_id;
field_index(imsi)                -> #aaa_session.imsi;
field_index(nai)                 -> #aaa_session.nai;
field_index(interface)           -> #aaa_session.interface;
field_index(origin_host)         -> #aaa_session.origin_host;
field_index(origin_realm)        -> #aaa_session.origin_realm;
field_index(apn)                 -> #aaa_session.apn;
field_index(rat_type)            -> #aaa_session.rat_type;
field_index(an_trusted)          -> #aaa_session.an_trusted;
field_index(visited_plmn)        -> #aaa_session.visited_plmn;
field_index(ue_local_ip)         -> #aaa_session.ue_local_ip;
field_index(eap_id)              -> #aaa_session.eap_id;
field_index(eap_state)           -> #aaa_session.eap_state;
field_index(method)              -> #aaa_session.method;
field_index(rand)                -> #aaa_session.rand;
field_index(autn)                -> #aaa_session.autn;
field_index(xres)                -> #aaa_session.xres;
field_index(ck)                  -> #aaa_session.ck;
field_index(ik)                  -> #aaa_session.ik;
field_index(network_name)        -> #aaa_session.network_name;
field_index(k_encr)              -> #aaa_session.k_encr;
field_index(k_aut)               -> #aaa_session.k_aut;
field_index(k_re)                -> #aaa_session.k_re;
field_index(msk)                 -> #aaa_session.msk;
field_index(emsk)                -> #aaa_session.emsk;
field_index(pseudonym)           -> #aaa_session.pseudonym;
field_index(reauth_id)           -> #aaa_session.reauth_id;
field_index(non_3gpp_user_data)  -> #aaa_session.non_3gpp_user_data;
field_index(apn_configuration)   -> #aaa_session.apn_configuration;
field_index(ambr_ul)             -> #aaa_session.ambr_ul;
field_index(ambr_dl)             -> #aaa_session.ambr_dl;
field_index(pgw_id)              -> #aaa_session.pgw_id;
field_index(expiry_ts)           -> #aaa_session.expiry_ts;
field_index(_)                   -> undefined.

%% @doc Pipelined GET of every SessionId referenced by an index set.
%% Uses MGET so fetching all sessions for one IMSI or one interface
%% is a single Redis round-trip. Skips members whose blob has already
%% expired (the index set is scrubbed lazily by the cleanup timer).
mget_sessions([]) -> [];
mget_sessions(Ids) ->
    case aaa_redis:q([<<"MGET">> | [sess_key(Id) || Id <- Ids]]) of
        {ok, Blobs} when is_list(Blobs), length(Blobs) =:= length(Ids) ->
            [S || {_Id, Blob} <- lists:zip(Ids, Blobs),
                  is_binary(Blob),
                  {ok, S} <- [safe_binary_to_session(Blob)]];
        _ ->
            %% Fallback: issue individual GETs so the API remains
            %% robust if MGET is unavailable for some reason.
            lists:foldr(
                fun(Id, Acc) ->
                    case get_session(Id) of
                        {ok, S} -> [S | Acc];
                        error   -> Acc
                    end
                end, [], Ids)
    end.

safe_binary_to_session(Blob) ->
    try
        {ok, binary_to_term(Blob, [safe])}
    catch
        _:_ -> error
    end.

%% @doc Iterate SCAN cursors for a match pattern and return the
%% collected keys. Bounded at 10k keys to avoid pathological runtimes.
scan_keys(Pattern) ->
    scan_keys(<<"0">>, Pattern, [], 0).

scan_keys(_Cursor, _Pattern, Acc, N) when N >= 10000 ->
    lists:append(lists:reverse(Acc));
scan_keys(Cursor, Pattern, Acc, N) ->
    case aaa_redis:q([<<"SCAN">>, Cursor,
                      <<"MATCH">>, Pattern,
                      <<"COUNT">>, <<"200">>]) of
        {ok, [NextCursor, Keys]} when is_list(Keys) ->
            case NextCursor of
                <<"0">> ->
                    lists:append(lists:reverse([Keys | Acc]));
                _ ->
                    scan_keys(NextCursor, Pattern,
                              [Keys | Acc], N + length(Keys))
            end;
        _ ->
            lists:append(lists:reverse(Acc))
    end.

%% Periodic lightweight GC: walk each interface set, drop SessionIds
%% whose blob has already expired so SCARD-based metrics stay honest.
prune_interface_sets() ->
    lists:foreach(fun prune_iface/1, [swm, sta, s6b]).

prune_iface(Iface) ->
    case aaa_redis:smembers(iface_key(Iface)) of
        {ok, []}   -> ok;
        {ok, Ids}  -> prune_iface_ids(Iface, Ids);
        _          -> ok
    end.

prune_iface_ids(_Iface, []) -> ok;
prune_iface_ids(Iface, Ids) ->
    {Chunk, Rest} = case length(Ids) > ?PRUNE_CHUNK of
        true  -> lists:split(?PRUNE_CHUNK, Ids);
        false -> {Ids, []}
    end,
    case aaa_redis:q([<<"MGET">> | [sess_key(Id) || Id <- Chunk]]) of
        {ok, Blobs} when is_list(Blobs), length(Blobs) =:= length(Chunk) ->
            Dead = [Id || {Id, undefined} <- lists:zip(Chunk, Blobs)],
            remove_dead_members(Iface, Dead),
            prune_iface_ids(Iface, Rest);
        _ -> ok
    end.

%% SET NX with a TTL: the first pod of the minute prunes, the others skip.
%% A failed Redis call counts as "not claimed", so a pod never prunes
%% while the store is in trouble.
claim_prune_lock() ->
    Key = aaa_redis:key([<<"gc:lock">>]),
    case aaa_redis:q([<<"SET">>, Key, atom_to_binary(node(), utf8),
                      <<"NX">>, <<"EX">>, integer_to_binary(?PRUNE_LOCK_TTL_SEC)]) of
        {ok, <<"OK">>} -> true;
        _              -> false
    end.

remove_dead_members(_Iface, []) -> ok;
remove_dead_members(Iface, Dead) ->
    IKey = iface_key(Iface),
    _ = aaa_redis:q([<<"SREM">>, IKey | Dead]),
    ok.

refresh_active_gauge() ->
    Counts = [{I, count(I)} || I <- [swm, sta, s6b]],
    lists:foreach(fun({I, N}) -> aaa_metrics:gauge_set(gauge_name(I), N) end,
                  Counts),
    aaa_metrics:gauge_set(active_sessions, lists:sum([N || {_, N} <- Counts])),
    ok.

gauge_name(swm) -> active_sessions_swm;
gauge_name(sta) -> active_sessions_sta;
gauge_name(s6b) -> active_sessions_s6b.
