%%%-------------------------------------------------------------------
%%% @doc CT suite for the DRA transport rebuild rule of aaa_diameter_svc.
%%%
%%% KI-40: 15 s after every DRA peer-down the service removed and re-added
%%% the transport, although OTP had usually reconnected it already. That
%%% transport also carries the DRA's SWm and S6b requests to this AAA, so
%%% each peer drop became two outages. The rule under test decides when a
%%% rebuild is warranted. Pure function, no Diameter stack needed.
%%% @end
%%%-------------------------------------------------------------------
-module(aaa_diameter_svc_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0]).
-export([peer_recovered_keeps_transport/1,
         dns_failure_while_up_keeps_transport/1,
         address_change_rebuilds/1,
         peer_still_down_rebuilds/1,
         unknown_state_rebuilds/1]).

all() ->
    [peer_recovered_keeps_transport,
     dns_failure_while_up_keeps_transport,
     address_change_rebuilds,
     peer_still_down_rebuilds,
     unknown_state_rebuilds].

-define(DRA, {10, 244, 1, 175}).
-define(DRA2, {10, 244, 1, 176}).

%% The common case: OTP reconnected within the grace period and DNS still
%% names the same address. Rebuilding would drop the recovered connection.
peer_recovered_keeps_transport(_) ->
    keep = aaa_diameter_svc:reconnect_decision(up, ?DRA, {ok, ?DRA}),
    ok.

%% A DNS hiccup is no reason to drop a working connection.
dns_failure_while_up_keeps_transport(_) ->
    keep = aaa_diameter_svc:reconnect_decision(up, ?DRA, {error, nxdomain}),
    ok.

%% The DRA pod was recreated with a new address: OTP would retry the old
%% one forever, so the transport must be rebuilt even though a peer came up.
address_change_rebuilds(_) ->
    rebuild = aaa_diameter_svc:reconnect_decision(up, ?DRA, {ok, ?DRA2}),
    ok.

peer_still_down_rebuilds(_) ->
    rebuild = aaa_diameter_svc:reconnect_decision(down, ?DRA, {ok, ?DRA}),
    ok.

%% Missing information never turns into "do nothing": the rule falls back
%% to the previous behaviour, a rebuild.
unknown_state_rebuilds(_) ->
    rebuild = aaa_diameter_svc:reconnect_decision(unknown, ?DRA, {ok, ?DRA}),
    rebuild = aaa_diameter_svc:reconnect_decision(up, undefined, {ok, ?DRA}),
    ok.
