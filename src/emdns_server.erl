%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%% 
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%% 
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%% 
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%% 
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.

-module(emdns_server).
-behaviour(gen_server).

-include("emdns.hrl").

-define(SERVER, ?MODULE).

-record(state, {
        debug = false,  % packet dump
        s,              % socket
        r = []          % registered clients
    }).

-export([send/1,
        register/0, unregister/0,
        debug/1,
        stop/0]).
-export([start_link/0, start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).


%% API
stop() ->
    gen_server:call(?SERVER, stop).

register() ->
    gen_server:call(?SERVER, {register, add}).
unregister() ->
    gen_server:call(?SERVER, {register, delete}).

debug(Val) when Val == true; Val == false ->
    gen_server:call(?SERVER, {debug, Val}).


send(#dns_rec{} = Query) ->
    send(inet_dns:encode(Query));
send(Query) when is_binary(Query) ->
    gen_server:cast(?SERVER, {dns_query, Query}).


%%
%% gen_server callbacks
%%
start_link() ->
    start_link(?MDNS_PORT).
start_link(Port) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Port], []).

init([Port]) ->
    {ok, Socket} = gen_udp:open(Port, [binary]),
    {ok, {InterfaceAddress, _Port}} = inet:sockname(Socket),
    ok = inet:setopts(Socket, [
            {add_membership,{?MDNS_ADDRESS, InterfaceAddress}}
        ]),
    {ok, #state{s = Socket}}.


% Add/remove notification to a process. 
handle_call({register, add}, {Pid,_Tag}, #state{r = Registered} = State) ->
    erlang:monitor(process, Pid),
    {reply, ok, State#state{r = [Pid|Registered]}};
handle_call({register, delete}, {Pid,_Tag}, #state{r = Registered} = State) ->
    erlang:demonitor(Pid),
    {reply, ok, State#state{r = Registered -- [Pid]}};

% Log packets to console
handle_call({debug, Val}, _From, State) ->
    {reply, ok, State#state{debug = Val}};

handle_call(stop, _From, #state{s = Socket} = State) ->
    {ok, {InterfaceAddress, _Port}} = inet:sockname(Socket),
    Result = inet:setopts(Socket, [
            {drop_membership,{?MDNS_ADDRESS, InterfaceAddress}}
        ]),
    {stop, shutdown, Result, State};

handle_call(Request, _From, State) ->
    error_logger:error_report([{request, Request}, {state, State}]),
    {reply, ok, State}.


handle_cast({dns_query, Query}, #state{s = Socket} = State) ->
    ok = gen_udp:send(Socket, ?MDNS_ADDRESS, ?MDNS_PORT, Query),
    {noreply, State};
handle_cast(Request, State) ->
    error_logger:error_report([{request, Request}, {state, State}]),
    {noreply, State}.

handle_info({udp, Socket, IP, InPortNo, Packet},
    #state{s = Socket, r = Registered, debug = Debug} = State) ->
    case Debug of
        true ->
            error_logger:info_report([
                {ip, IP},
                {source_port, InPortNo},
                {response, Packet},
                {decoded, inet_dns:decode(Packet)}
            ]);
        false ->
            ok
    end,
    [ Pid ! {emdns, IP, InPortNo, Packet} || Pid <- Registered ],
    {noreply, State};
handle_info({'DOWN', MonitorRef, process, _Object, _Info}, #state{r = Registered} = State) ->
    {noreply, State#state{r = Registered -- MonitorRef}};
handle_info(Info, State) ->
    error_logger:error_report([{wtf, Info}, {state, State}]),
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%
%% Internal Functions
%%


