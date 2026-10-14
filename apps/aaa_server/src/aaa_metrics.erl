%%%-------------------------------------------------------------------
%%% @doc Prometheus-style metrics for AAA Server.
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_metrics).

-export([init/0, inc/1, inc/2,
         gauge_inc/1, gauge_dec/1, gauge_set/2,
         observe_latency/2,
         get/1, format_prometheus/0]).

-define(TAB, aaa_metrics_tab).

init() ->
    case ets:info(?TAB) of
        undefined -> ets:new(?TAB, [named_table, public, set, {write_concurrency, true}]);
        _ -> ok
    end,
    lists:foreach(fun(K) -> ets:insert_new(?TAB, {K, 0}) end, [
        swm_requests_total,
        swm_auth_success_total,
        swm_auth_failure_total,
        swm_asr_total,
        swm_rar_total,
        swm_latency_ms_sum,
        swm_latency_ms_count,
        swm_peers,
        swx_mar_total,
        swx_sar_total,
        swx_rtr_total,
        swx_ppr_total,
        swx_errors_total,
        swx_latency_ms_sum,
        swx_latency_ms_count,
        swx_peers,
        s6b_requests_total,
        s6b_auth_success_total,
        s6b_auth_failure_total,
        s6b_asr_total,
        s6b_rar_total,
        s6b_latency_ms_sum,
        s6b_latency_ms_count,
        s6b_peers,
        sta_requests_total,
        sta_auth_success_total,
        sta_auth_failure_total,
        sta_asr_total,
        sta_rar_total,
        sta_latency_ms_sum,
        sta_latency_ms_count,
        sta_peers,
        radius_access_request_total,
        radius_access_accept_total,
        radius_access_reject_total,
        radius_access_challenge_total,
        radius_bad_mac_total,
        active_sessions,
        active_sessions_swm,
        active_sessions_sta,
        active_sessions_s6b,
        sessions_superseded_total,
        sessions_orphaned_total,
        swm_asr_from_s6b_total,
        redis_oom_errors_total,
        dra_transport_rebuilds_total,
        eap_relay_total,
        eap_relay_success_total,
        eap_relay_failure_total,
        redis_ops_total,
        redis_errors_total,
        redis_connects_total,
        redis_connect_errors_total,
        redis_disconnects_total,
        redis_connected,
        redis_latency_ms_sum,
        redis_latency_ms_count
    ]),
    ok.

-spec inc(atom()) -> ok.
inc(Key) -> inc(Key, 1).

-spec inc(atom(), integer()) -> ok.
inc(Key, N) ->
    ensure_tab(),
    try ets:update_counter(?TAB, Key, N)
    catch error:badarg -> ets:insert(?TAB, {Key, N})
    end, ok.

-spec gauge_inc(atom()) -> ok.
gauge_inc(Key) -> inc(Key, 1).

-spec gauge_dec(atom()) -> ok.
gauge_dec(Key) ->
    ensure_tab(),
    try ets:update_counter(?TAB, Key, -1) catch error:badarg -> ok end, ok.

-spec gauge_set(atom(), integer()) -> ok.
gauge_set(Key, Val) ->
    ensure_tab(),
    ets:insert(?TAB, {Key, Val}), ok.

-spec get(atom()) -> integer().
get(Key) ->
    ensure_tab(),
    case ets:lookup(?TAB, Key) of [{_, V}] -> V; [] -> 0 end.

%% @doc Create the metrics table if it vanished (e.g. between CT test
%% cases after init_per_suite's owner process exited). `inc/2' and
%% friends are called from every Diameter, EAP and Redis worker so we
%% cannot rely on `aaa_metrics:init/0' having been called first, and
%% a named public ETS table is destroyed as soon as its owning
%% process exits. We therefore spawn a dedicated owner proc that
%% outlives any caller — on production boot `aaa_app:start/2' still
%% calls `init/0' explicitly up-front.
ensure_tab() ->
    case ets:info(?TAB) of
        undefined ->
            Owner = ensure_owner(),
            %% Race-safe: the owner serialises table creation.
            Owner ! {ensure_table, self()},
            receive
                {aaa_metrics_tab_ready} -> ok
            after 5000 -> ok
            end;
        _ -> ok
    end.

ensure_owner() ->
    case erlang:whereis(aaa_metrics_owner) of
        undefined ->
            Pid = spawn(fun owner_loop/0),
            case catch register(aaa_metrics_owner, Pid) of
                true -> Pid;
                _    ->
                    %% Another process won the race.
                    exit(Pid, kill),
                    erlang:whereis(aaa_metrics_owner)
            end;
        P -> P
    end.

owner_loop() ->
    receive
        {ensure_table, From} ->
            case ets:info(?TAB) of
                undefined -> init();
                _         -> ok
            end,
            From ! {aaa_metrics_tab_ready},
            owner_loop();
        _ ->
            owner_loop()
    end.

-spec observe_latency(atom(), non_neg_integer()) -> ok.
observe_latency(Prefix, DurationMs) ->
    inc(list_to_atom(atom_to_list(Prefix) ++ "_ms_sum"), DurationMs),
    inc(list_to_atom(atom_to_list(Prefix) ++ "_ms_count")),
    ok.

-spec format_prometheus() -> iolist().
format_prometheus() ->
    [io_lib:format("aaa_~s ~B\n", [K, V]) || {K, V} <- lists:sort(ets:tab2list(?TAB))].
