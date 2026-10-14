%%%-------------------------------------------------------------------
%%% @doc Pooled Redis client facade used by `aaa_session_mgr'.
%%%
%%% Owns a small fixed pool of `aaa_redis_worker' processes and
%%% dispatches individual commands / pipelines across them using a
%%% round-robin counter in ETS so concurrent DER handlers don't
%%% serialise on a single connection.
%%%
%%% The pool is intentionally simple — no poolboy. Every worker holds
%%% one eredis connection; dead workers reconnect autonomously. If
%%% every worker is down, command calls return `{error, redis_unavailable}'
%%% and the Diameter layer returns `DIAMETER_UNABLE_TO_COMPLY' so the
%%% ePDG / PGW can retry.
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_redis).

-behaviour(supervisor).

-export([start_link/0, start_link/1]).
-export([init/1]).

-export([
    q/1, q/2,
    get/1, set/2, set/3, setex/3, del/1, expire/2, exists/1,
    sadd/2, srem/2, smembers/1,
    multi/1,
    ping/0,
    dbsize/0, scard/1,
    key/1, key_prefix/0
]).

-define(SUP, ?MODULE).
-define(TAB_ROUTE, aaa_redis_route).

%%====================================================================
%% Supervisor API
%%====================================================================

start_link() ->
    start_link(pool_opts()).

start_link(Opts) when is_map(Opts) ->
    supervisor:start_link({local, ?SUP}, ?MODULE, Opts).

init(Opts) ->
    ensure_route_tab(),
    PoolSize = maps:get(pool_size, Opts, 8),
    WorkerOpts = maps:without([pool_size], Opts),
    Workers = [worker_spec(I, WorkerOpts) || I <- lists:seq(1, PoolSize)],
    ets:insert(?TAB_ROUTE, {pool_size, PoolSize}),
    SupFlags = #{strategy => one_for_one, intensity => 20, period => 60},
    {ok, {SupFlags, Workers}}.

worker_spec(Ix, Opts) ->
    Name = worker_name(Ix),
    #{id      => Name,
      start   => {aaa_redis_worker, start_link, [Name, Opts]},
      restart => permanent, shutdown => 5000, type => worker}.

worker_name(Ix) ->
    list_to_atom("aaa_redis_w_" ++ integer_to_list(Ix)).

ensure_route_tab() ->
    case ets:info(?TAB_ROUTE) of
        undefined ->
            ets:new(?TAB_ROUTE, [named_table, public, set,
                                 {write_concurrency, true},
                                 {read_concurrency, true}]),
            ets:insert(?TAB_ROUTE, {rr, 0});
        _ -> ok
    end.

%%====================================================================
%% Command API
%%====================================================================

%% @doc Dispatch a single Redis command. `Cmd' is a list of
%% iodata/binaries as accepted by eredis.
-spec q([iodata()]) -> {ok, term()} | {error, term()}.
q(Cmd) -> q(Cmd, 5000).

-spec q([iodata()], non_neg_integer()) -> {ok, term()} | {error, term()}.
q(Cmd, Timeout) ->
    case pick_worker() of
        undefined -> {error, redis_unavailable};
        W         -> aaa_redis_worker:q(W, Cmd, Timeout)
    end.

-spec get(iodata()) -> {ok, binary() | undefined} | {error, term()}.
get(Key) ->
    q([<<"GET">>, Key]).

-spec set(iodata(), iodata()) -> ok | {error, term()}.
set(Key, Val) ->
    case q([<<"SET">>, Key, Val]) of
        {ok, <<"OK">>} -> ok;
        Err            -> Err
    end.

-spec set(iodata(), iodata(), non_neg_integer()) -> ok | {error, term()}.
set(Key, Val, TtlSec) when is_integer(TtlSec), TtlSec > 0 ->
    setex(Key, TtlSec, Val);
set(Key, Val, _) ->
    set(Key, Val).

-spec setex(iodata(), non_neg_integer(), iodata()) -> ok | {error, term()}.
setex(Key, TtlSec, Val) when is_integer(TtlSec), TtlSec > 0 ->
    case q([<<"SETEX">>, Key, integer_to_binary(TtlSec), Val]) of
        {ok, <<"OK">>} -> ok;
        Err            -> Err
    end.

-spec del(iodata()) -> {ok, integer()} | {error, term()}.
del(Key) when is_binary(Key) ->
    q([<<"DEL">>, Key]);
del(Key) ->
    q([<<"DEL">>, iolist_to_binary(Key)]).

-spec expire(iodata(), non_neg_integer()) -> {ok, integer()} | {error, term()}.
expire(Key, TtlSec) when is_integer(TtlSec), TtlSec > 0 ->
    q([<<"EXPIRE">>, Key, integer_to_binary(TtlSec)]).

-spec exists(iodata()) -> boolean() | {error, term()}.
exists(Key) ->
    case q([<<"EXISTS">>, Key]) of
        {ok, <<"1">>} -> true;
        {ok, <<"0">>} -> false;
        Err           -> Err
    end.

-spec sadd(iodata(), iodata() | [iodata()]) -> {ok, integer()} | {error, term()}.
sadd(Key, Members) when is_list(Members), Members =/= [],
                        not is_integer(hd(Members)) ->
    q([<<"SADD">>, Key | Members]);
sadd(Key, Member) ->
    q([<<"SADD">>, Key, Member]).

-spec srem(iodata(), iodata()) -> {ok, integer()} | {error, term()}.
srem(Key, Member) ->
    q([<<"SREM">>, Key, Member]).

-spec smembers(iodata()) -> {ok, [binary()]} | {error, term()}.
smembers(Key) ->
    q([<<"SMEMBERS">>, Key]).

-spec scard(iodata()) -> {ok, integer()} | {error, term()}.
scard(Key) ->
    q([<<"SCARD">>, Key]).

-spec dbsize() -> {ok, integer()} | {error, term()}.
dbsize() ->
    q([<<"DBSIZE">>]).

%% @doc Execute a MULTI/EXEC transaction. `Cmds' is a list of
%% command lists exactly as accepted by `q/1'. Returns the parsed EXEC
%% reply on success.
-spec multi([[iodata()]]) -> {ok, [term()]} | {error, term()}.
multi(Cmds) when is_list(Cmds) ->
    case pick_worker() of
        undefined ->
            {error, redis_unavailable};
        W ->
            Pipeline = [[<<"MULTI">>]] ++ Cmds ++ [[<<"EXEC">>]],
            case aaa_redis_worker:qp(W, Pipeline) of
                Replies when is_list(Replies) ->
                    %% A write refused inside the block (Redis at
                    %% `maxmemory' answers each queued command with OOM)
                    %% only shows as EXECABORT on the EXEC reply; hand the
                    %% refusal itself to the caller.
                    case [R || {error, <<"OOM", _/binary>> = R} <- Replies] of
                        [Oom | _] -> {error, Oom};
                        []        -> parse_multi(Replies)
                    end;
                {error, _} = E ->
                    E
            end
    end.

-spec ping() -> ok | {error, term()}.
ping() ->
    case pick_worker() of
        undefined -> {error, redis_unavailable};
        W         -> aaa_redis_worker:ping(W)
    end.

%%====================================================================
%% Key helpers
%%====================================================================

-spec key(iodata()) -> binary().
key(Suffix) ->
    iolist_to_binary([key_prefix(), Suffix]).

-spec key_prefix() -> binary().
key_prefix() ->
    case aaa_config:get(redis_key_prefix, <<"aaa:">>) of
        B when is_binary(B) -> B;
        L when is_list(L)   -> list_to_binary(L)
    end.

%%====================================================================
%% Internal
%%====================================================================

pool_opts() ->
    #{
        host            => aaa_config:get(redis_host, "aaa-redis"),
        port            => aaa_config:get(redis_port, 6379),
        database        => aaa_config:get(redis_db, 0),
        password        => aaa_config:get(redis_password, ""),
        pool_size       => aaa_config:get(redis_pool_size, 8),
        connect_timeout => aaa_config:get(redis_connect_timeout, 5000),
        reconnect_sleep => aaa_config:get(redis_reconnect_sleep, 500)
    }.

pick_worker() ->
    case ets:info(?TAB_ROUTE) of
        undefined -> undefined;
        _ ->
            Size = case ets:lookup(?TAB_ROUTE, pool_size) of
                [{_, N}] when is_integer(N), N > 0 -> N;
                _ -> 0
            end,
            case Size of
                0 -> undefined;
                _ ->
                    N0 = try ets:update_counter(?TAB_ROUTE, rr, {2, 1})
                         catch error:badarg ->
                             ets:insert(?TAB_ROUTE, {rr, 1}), 1
                         end,
                    Ix = ((N0 - 1) rem Size) + 1,
                    Name = worker_name(Ix),
                    case whereis(Name) of
                        undefined -> scan_alive(Size);
                        Pid when is_pid(Pid) -> Name
                    end
            end
    end.

scan_alive(0) -> undefined;
scan_alive(Size) -> scan_alive(Size, Size).

scan_alive(0, _Size) -> undefined;
scan_alive(Remaining, Size) ->
    Ix = (Size - Remaining + 1),
    Name = worker_name(Ix),
    case whereis(Name) of
        undefined -> scan_alive(Remaining - 1, Size);
        _Pid      -> Name
    end.

parse_multi(Replies) ->
    case lists:last(Replies) of
        {ok, ExecResult} when is_list(ExecResult) ->
            {ok, ExecResult};
        {ok, undefined} ->
            {error, transaction_aborted};
        {error, R} ->
            {error, R};
        Other ->
            {error, {unexpected_exec, Other}}
    end.
