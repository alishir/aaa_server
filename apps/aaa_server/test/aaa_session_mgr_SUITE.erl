%%%-------------------------------------------------------------------
%%% @doc CT suite for aaa_session_mgr — exercises the dual IMSI ↔
%%% Session-Id index and NAI binding used to correlate HSS-initiated
%%% RTR/PPR (SWx) to active SWm/S6b sessions, plus the cross-pod
%%% resume semantics that the Redis-backed store enables.
%%%
%%% Requires a reachable Redis. The suite auto-skips when Redis is
%%% not available unless `AAA_REDIS_REQUIRED=1' is set in the env.
%%% Configure the target with `AAA_REDIS_HOST' / `AAA_REDIS_PORT'
%%% (defaults 127.0.0.1:6379). Each test case flushes a dedicated
%%% DB (default 15, override via `AAA_REDIS_TEST_DB') to avoid
%%% stepping on production data.
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_session_mgr_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../include/aaa_session.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).
-export([
    create_and_lookup/1,
    dual_index/1,
    multiple_sessions_per_imsi/1,
    nai_binding/1,
    remove_by_imsi/1,
    count_by_interface/1,
    cross_pod_resume/1,
    ttl_expiry/1,
    multi_atomicity/1,
    redis_restart_tolerant/1,
    supersede_replaces_same_interface_session/1,
    supersede_keeps_other_apn_on_s6b/1,
    prune_is_chunked_and_single_runner/1,
    store_full_reports_oom/1,
    str_followup_deregisters_only_after_the_last_session/1,
    end_session_reports_what_remains/1
]).

-define(TEST_PREFIX, <<"aaa_test:">>).

suite() -> [{timetrap, {seconds, 60}}].

all() ->
    [create_and_lookup,
     dual_index,
     multiple_sessions_per_imsi,
     nai_binding,
     remove_by_imsi,
     count_by_interface,
     cross_pod_resume,
     ttl_expiry,
     multi_atomicity,
     redis_restart_tolerant,
     supersede_replaces_same_interface_session,
     supersede_keeps_other_apn_on_s6b,
     prune_is_chunked_and_single_runner,
     store_full_reports_oom,
     str_followup_deregisters_only_after_the_last_session,
     end_session_reports_what_remains].

init_per_suite(Config) ->
    ok = aaa_metrics:init(),
    Host = getenv("AAA_REDIS_HOST", "127.0.0.1"),
    Port = list_to_integer(getenv("AAA_REDIS_PORT", "6379")),
    Db   = list_to_integer(getenv("AAA_REDIS_TEST_DB", "15")),
    case probe_redis(Host, Port) of
        ok ->
            application:load(aaa_server),
            application:set_env(aaa_server, redis_host, Host),
            application:set_env(aaa_server, redis_port, Port),
            application:set_env(aaa_server, redis_db,   Db),
            application:set_env(aaa_server, redis_password, ""),
            application:set_env(aaa_server, redis_pool_size, 2),
            application:set_env(aaa_server, redis_connect_timeout, 3000),
            application:set_env(aaa_server, redis_reconnect_sleep, 250),
            application:set_env(aaa_server, redis_key_prefix, ?TEST_PREFIX),
            application:set_env(aaa_server, session_timeout, 300),
            application:ensure_all_started(eredis),
            [{redis_host, Host}, {redis_port, Port}, {redis_db, Db} | Config];
        {error, Reason} ->
            case getenv("AAA_REDIS_REQUIRED", "0") of
                "1" ->
                    ct:fail({redis_unavailable, Reason});
                _ ->
                    {skip, {"Redis unreachable at "
                            ++ Host ++ ":" ++ integer_to_list(Port),
                            Reason}}
            end
    end.

end_per_suite(_Config) -> ok.

init_per_testcase(_TC, Config) ->
    %% We selectively bring down the Redis supervisor inside some
    %% cases (cross_pod_resume, redis_restart_tolerant) to simulate a
    %% Redis outage — the testcase process has to trap exits so the
    %% shutdown signal from the linked start_link does not take the
    %% test down with it.
    process_flag(trap_exit, true),
    {ok, SupPid} = aaa_redis:start_link(),
    ok = wait_for_redis_ready(20),
    flush_test_keys(),
    {ok, MgrPid} = aaa_session_mgr:start_link(),
    [{redis_sup, SupPid}, {mgr, MgrPid} | Config].

end_per_testcase(_TC, Config) ->
    flush_test_keys(),
    MgrPid = ?config(mgr, Config),
    case MgrPid =/= undefined andalso is_process_alive(MgrPid) of
        true  -> gen_server:stop(MgrPid);
        false -> ok
    end,
    SupPid = ?config(redis_sup, Config),
    case SupPid =/= undefined andalso is_process_alive(SupPid) of
        true  -> exit(SupPid, shutdown), wait_gone(SupPid, 50);
        false -> ok
    end,
    ok.

%%====================================================================
%% KI-46: sessions of ended attachments stayed in the store
%%====================================================================

%% A re-attach (new Session-Id) replaces the UE's earlier session on the
%% same interface; the session on the other interface is untouched.
supersede_replaces_same_interface_session(_Config) ->
    IMSI = <<"001010000000050">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"swm-old">>, imsi = IMSI, interface = swm}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"s6b-1">>, imsi = IMSI, interface = s6b,
                         apn = <<"ims">>}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"swm-new">>, imsi = IMSI, interface = swm}),
    [<<"swm-old">>] = aaa_session_mgr:supersede_sessions(swm, IMSI, <<"swm-new">>, undefined),
    error = aaa_session_mgr:get_session(<<"swm-old">>),
    {ok, _} = aaa_session_mgr:get_session(<<"swm-new">>),
    {ok, _} = aaa_session_mgr:get_session(<<"s6b-1">>),
    1 = aaa_session_mgr:count(swm),
    %% The alias index no longer points at the removed session.
    Ids = [S#aaa_session.session_id || S <- aaa_session_mgr:indexed_sessions_for_imsi(IMSI)],
    [<<"s6b-1">>, <<"swm-new">>] = lists:sort(Ids),
    %% Nothing to supersede the second time.
    [] = aaa_session_mgr:supersede_sessions(swm, IMSI, <<"swm-new">>, undefined),
    ok.

%% On S6b a UE may hold one PDN connection per APN: only the session of
%% the same APN is replaced.
supersede_keeps_other_apn_on_s6b(_Config) ->
    IMSI = <<"001010000000051">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"s6b-ims-old">>, imsi = IMSI,
                         interface = s6b, apn = <<"ims">>}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"s6b-internet">>, imsi = IMSI,
                         interface = s6b, apn = <<"internet">>}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"s6b-ims-new">>, imsi = IMSI,
                         interface = s6b, apn = <<"ims">>}),
    [<<"s6b-ims-old">>] = aaa_session_mgr:supersede_sessions(
                            s6b, IMSI, <<"s6b-ims-new">>, <<"ims">>),
    {ok, _} = aaa_session_mgr:get_session(<<"s6b-internet">>),
    {ok, _} = aaa_session_mgr:get_session(<<"s6b-ims-new">>),
    2 = aaa_session_mgr:count(s6b),
    ok.

%% The clean-up removes index members whose session expired, reading the
%% blobs in chunks (1,200 members exceed one chunk), and only the pod
%% that holds the lock does it.
prune_is_chunked_and_single_runner(_Config) ->
    IfaceKey = aaa_redis:key([<<"iface:swm">>]),
    Live = [list_to_binary("live-" ++ integer_to_list(N)) || N <- lists:seq(1, 600)],
    Dead = [list_to_binary("dead-" ++ integer_to_list(N)) || N <- lists:seq(1, 600)],
    lists:foreach(fun(Sid) ->
        ok = aaa_session_mgr:create_session(
               #aaa_session{session_id = Sid, imsi = Sid, interface = swm})
    end, Live),
    {ok, _} = aaa_redis:q([<<"SADD">>, IfaceKey | Dead]),
    1200 = aaa_session_mgr:count(swm),
    %% Another pod holds the lock: this pod must not prune.
    LockKey = aaa_redis:key([<<"gc:lock">>]),
    {ok, <<"OK">>} = aaa_redis:q([<<"SET">>, LockKey, <<"other-pod">>, <<"EX">>, <<"30">>]),
    ok = aaa_session_mgr:run_cleanup(),
    1200 = aaa_session_mgr:count(swm),
    %% Lock free: one pass removes every dead member and keeps the live ones.
    {ok, _} = aaa_redis:q([<<"DEL">>, LockKey]),
    ok = aaa_session_mgr:run_cleanup(),
    600 = aaa_session_mgr:count(swm),
    600 = length(aaa_session_mgr:sessions_by_interface(swm)),
    %% The pass left its own lock behind, so the next pod skips.
    {ok, Holder} = aaa_redis:q([<<"GET">>, LockKey]),
    true = is_binary(Holder),
    ok.

%% With `maxmemory' reached (policy noeviction) a new session is refused
%% with a distinct error, so the Diameter handlers can answer
%% UNABLE_TO_COMPLY instead of crashing.
store_full_reports_oom(_Config) ->
    {ok, [_, Before]} = aaa_redis:q([<<"CONFIG">>, <<"GET">>, <<"maxmemory">>]),
    {ok, _} = aaa_redis:q([<<"CONFIG">>, <<"SET">>, <<"maxmemory">>, <<"1">>]),
    try
        {error, redis_oom} = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"oom-1">>, imsi = <<"001010000000052">>,
                         interface = swm})
    after
        {ok, _} = aaa_redis:q([<<"CONFIG">>, <<"SET">>, <<"maxmemory">>, Before])
    end,
    ok.

%% TS 29.273: the HSS is told that the user left non-3GPP access (SWx SAR
%% type 5) when the last session is gone, not when the first one ends;
%% an S6b end with a SWm session left asks the ePDG to end the tunnel; a
%% SWm end with an S6b session left waits for the PGW's own STR.
str_followup_deregisters_only_after_the_last_session(_Config) ->
    Swm = #aaa_session{session_id = <<"swm">>, imsi = <<"1">>, interface = swm},
    S6b = #aaa_session{session_id = <<"s6b">>, imsi = <<"1">>, interface = s6b},
    [sar_deregistration] = aaa_session_mgr:str_followup(swm, []),
    [sar_deregistration] = aaa_session_mgr:str_followup(s6b, []),
    [{s6b_grace, S6b}] = aaa_session_mgr:str_followup(swm, [S6b]),
    [{swm_asr, Swm}] = aaa_session_mgr:str_followup(s6b, [Swm]),
    %% A second SWm session (re-attach in progress) is nobody's business here.
    [] = aaa_session_mgr:str_followup(swm, [Swm]),
    ok.

end_session_reports_what_remains(_Config) ->
    IMSI = <<"001010000000060">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"e-swm">>, imsi = IMSI, interface = swm}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"e-s6b">>, imsi = IMSI, interface = s6b,
                         apn = <<"ims">>}),
    {ok, #aaa_session{interface = swm}, [{s6b_grace, #aaa_session{session_id = <<"e-s6b">>}}]} =
        aaa_session_mgr:end_session(swm, <<"e-swm">>),
    error = aaa_session_mgr:get_session(<<"e-swm">>),
    {ok, #aaa_session{interface = s6b}, [sar_deregistration]} =
        aaa_session_mgr:end_session(s6b, <<"e-s6b">>),
    error = aaa_session_mgr:end_session(s6b, <<"e-s6b">>),
    0 = aaa_session_mgr:count(),
    ok.

%%====================================================================
%% Existing functional tests
%%====================================================================

create_and_lookup(_Config) ->
    S = #aaa_session{session_id = <<"sess-1">>, imsi = <<"001010000000001">>,
                     interface = swm, origin_host = <<"epdg.example.com">>},
    ok = aaa_session_mgr:create_session(S),
    {ok, Got} = aaa_session_mgr:get_session(<<"sess-1">>),
    <<"001010000000001">> = Got#aaa_session.imsi,
    swm = Got#aaa_session.interface,
    ok.

dual_index(_Config) ->
    IMSI = <<"001010000000002">>,
    Sid  = <<"sess-2">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = Sid, imsi = IMSI, interface = swm}),
    [Got] = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    Sid  = Got#aaa_session.session_id,
    ok.

multiple_sessions_per_imsi(_Config) ->
    IMSI = <<"001010000000003">>,
    Sid1 = <<"sess-3a">>, Sid2 = <<"sess-3b">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = Sid1, imsi = IMSI, interface = swm}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = Sid2, imsi = IMSI, interface = s6b}),
    List = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    2 = length(List),
    ok = aaa_session_mgr:remove_session(Sid1),
    [Remaining] = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    Sid2 = Remaining#aaa_session.session_id,
    ok.

nai_binding(_Config) ->
    NAI  = <<"7pseudo-abc@nai.epc.mnc001.mcc262.3gppnetwork.org">>,
    IMSI = <<"262010000000004">>,
    ok = aaa_session_mgr:bind_nai(NAI, IMSI),
    {ok, IMSI} = aaa_session_mgr:resolve_nai(NAI),
    error = aaa_session_mgr:resolve_nai(<<"no-such-nai">>),
    ok.

remove_by_imsi(_Config) ->
    IMSI = <<"001010000000005">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"x1">>, imsi = IMSI, interface = swm}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"x2">>, imsi = IMSI, interface = s6b}),
    Removed = aaa_session_mgr:remove_sessions_for_imsi(IMSI),
    true = is_list(Removed) andalso length(Removed) =:= 2,
    [] = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    error = aaa_session_mgr:get_session(<<"x1">>),
    error = aaa_session_mgr:get_session(<<"x2">>),
    ok.

count_by_interface(_Config) ->
    Initial = aaa_session_mgr:count(swm),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"c1">>, imsi = <<"1">>, interface = swm}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"c2">>, imsi = <<"2">>, interface = swm}),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = <<"c3">>, imsi = <<"3">>, interface = s6b}),
    After = aaa_session_mgr:count(swm),
    true = (After - Initial) >= 2,
    ok.

%%====================================================================
%% Redis-specific behaviour
%%====================================================================

%% Writes on "pod A", reads on "pod B": simulated by restarting the
%% session_mgr / redis pool in-process between write and read. The
%% Redis state persists so the session keys must still be there.
cross_pod_resume(Config) ->
    Sid  = <<"cross-pod-1">>,
    IMSI = <<"262010000000099">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = Sid, imsi = IMSI, interface = swm,
                         eap_state = challenge_sent,
                         method = aka_prime,
                         xres = <<1,2,3,4,5,6,7,8>>,
                         k_aut = binary:copy(<<16#aa>>, 16),
                         msk = binary:copy(<<16#bb>>, 64)}),

    %% Tear down the local pod's in-memory supervisor + mgr, then
    %% bring them back up — Redis is untouched.
    MgrPid = ?config(mgr, Config),
    gen_server:stop(MgrPid),
    SupPid = ?config(redis_sup, Config),
    exit(SupPid, shutdown), wait_gone(SupPid, 50),

    {ok, _} = aaa_redis:start_link(),
    ok = wait_for_redis_ready(20),
    {ok, _} = aaa_session_mgr:start_link(),

    {ok, Got} = aaa_session_mgr:get_session(Sid),
    challenge_sent = Got#aaa_session.eap_state,
    aka_prime      = Got#aaa_session.method,
    <<1,2,3,4,5,6,7,8>> = Got#aaa_session.xres,
    16 = byte_size(Got#aaa_session.k_aut),
    64 = byte_size(Got#aaa_session.msk),
    [Got2] = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    Sid = Got2#aaa_session.session_id,
    ok.

%% Session with expiry_ts 1 s in the future should disappear after
%% 2 s regardless of whether remove_session/1 was ever called.
ttl_expiry(_Config) ->
    Sid  = <<"ttl-1">>,
    IMSI = <<"262010000000100">>,
    Now  = erlang:system_time(second),
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = Sid, imsi = IMSI, interface = swm,
                         expiry_ts = Now + 1}),
    {ok, _} = aaa_session_mgr:get_session(Sid),
    timer:sleep(2500),
    error = aaa_session_mgr:get_session(Sid),
    ok.

%% If any command inside a MULTI fails, the transaction is rejected
%% and no index set gains a stale member. We force failure by
%% injecting a SET command on a list-typed key.
multi_atomicity(_Config) ->
    %% Poison a key so SADD will fail with WRONGTYPE — we use an
    %% internal IMSI index key directly.
    Poison = iolist_to_binary([?TEST_PREFIX, <<"imsi:poison-imsi">>]),
    {ok, _} = aaa_redis:q([<<"SET">>, Poison, <<"not-a-set">>]),

    Sid = <<"multi-1">>,
    Res = aaa_session_mgr:create_session(
             #aaa_session{session_id = Sid,
                          imsi = <<"poison-imsi">>,
                          interface = swm}),
    %% Either the create returns an error, or the index set still
    %% doesn't contain the session id (if Redis silently rejected
    %% just the offending SADD).
    case Res of
        {error, _} -> ok;
        ok ->
            %% In the degenerate case where Redis didn't abort the
            %% transaction, the poisoned key type should still not
            %% contain our member.
            {ok, T} = aaa_redis:q([<<"TYPE">>, Poison]),
            case T of
                <<"string">> -> ok;
                _            -> ct:fail({poison_key_type_changed, T})
            end
    end,
    ok.

%% Transient Redis failures must not take the session_mgr down; once
%% the pool reconnects the store becomes usable again. We simulate a
%% disconnect by stopping the pool supervisor and exercising the API
%% in the gap.
redis_restart_tolerant(Config) ->
    Sid  = <<"restart-1">>,
    IMSI = <<"262010000000101">>,
    ok = aaa_session_mgr:create_session(
            #aaa_session{session_id = Sid, imsi = IMSI, interface = swm}),
    {ok, _} = aaa_session_mgr:get_session(Sid),

    SupPid = ?config(redis_sup, Config),
    exit(SupPid, shutdown), wait_gone(SupPid, 50),

    %% With the pool gone the manager should return error / []
    %% without crashing.
    error = aaa_session_mgr:get_session(Sid),
    []    = aaa_session_mgr:get_sessions_for_imsi(IMSI),

    {ok, _} = aaa_redis:start_link(),
    ok = wait_for_redis_ready(20),

    {ok, _} = aaa_session_mgr:get_session(Sid),
    [_]     = aaa_session_mgr:get_sessions_for_imsi(IMSI),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

getenv(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Val   -> Val
    end.

probe_redis(Host, Port) ->
    case gen_tcp:connect(Host, Port, [binary, {active, false}], 1000) of
        {ok, Sock} ->
            gen_tcp:send(Sock, <<"PING\r\n">>),
            Res = case gen_tcp:recv(Sock, 0, 1000) of
                {ok, _} -> ok;
                {error, R} -> {error, R}
            end,
            catch gen_tcp:close(Sock),
            Res;
        {error, R} ->
            {error, R}
    end.

wait_for_redis_ready(0) -> {error, timeout};
wait_for_redis_ready(N) ->
    case aaa_redis:ping() of
        ok              -> ok;
        {error, _}      ->
            timer:sleep(100),
            wait_for_redis_ready(N - 1)
    end.

flush_test_keys() ->
    %% Scan + DEL all keys under the test prefix. Avoid FLUSHDB in
    %% case somebody points the suite at a shared Redis.
    flush_scan(<<"0">>).

flush_scan(Cursor) ->
    Pattern = iolist_to_binary([?TEST_PREFIX, <<"*">>]),
    case aaa_redis:q([<<"SCAN">>, Cursor, <<"MATCH">>, Pattern,
                      <<"COUNT">>, <<"500">>]) of
        {ok, [Next, Keys]} when is_list(Keys) ->
            case Keys of
                [] -> ok;
                _  -> _ = aaa_redis:q([<<"DEL">> | Keys]), ok
            end,
            case Next of
                <<"0">> -> ok;
                _       -> flush_scan(Next)
            end;
        _ -> ok
    end.

wait_gone(_Pid, 0) -> ok;
wait_gone(Pid, N) ->
    case is_process_alive(Pid) of
        false -> ok;
        true  -> timer:sleep(20), wait_gone(Pid, N - 1)
    end.
