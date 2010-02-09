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

-module(emdns).

-include_lib("kernel/include/inet.hrl").
-include("emdns.hrl").

-define(TTL_SHORT, 120).
-define(TTL_LONG, 4500).

-export([ttl/1, type/1, encode/1, service/1]).
-export([hostname/0,local_address/0,reverse_address/1]).


%%%
%%% Record construction
%%%
ttl(short) ->
    ?TTL_SHORT;
ttl(long) ->
    ?TTL_LONG.


type(header) ->
    % standard, authoritative mdns header
    #dns_header{
        id = 0,
        opcode = ?QUERY,
        aa = ?TRUE, % authoritative
        qr = ?TRUE  % response flag
    };

type({ptr, L}) when is_list(L) ->
    Domain = proplists:get_value(domain, L, reverse_address(local_address())),
    Class = proplists:get_value(class, L, in),
    TTL = proplists:get_value(ttl, L, ?TTL_SHORT),
    Data = proplists:get_value(data, L, hostname()),

    #dns_rr{
        domain = Domain,
        type = ptr,
        class = Class,
        ttl = TTL,
        data = Data
    };

type({srv, L}) when is_list(L) ->
    Domain = proplists:get_value(domain, L, hostname()),
    Class = proplists:get_value(class, L, in),
    TTL = proplists:get_value(ttl, L, ?TTL_SHORT),
    Data = proplists:get_value(data, L, hostname()),

    case Data of
        {A,B,C,D} when is_integer(A), is_integer(B), is_integer(C), is_list(D) ->
            #dns_rr{
                domain = Domain,
                type = srv,
                class = Class,
                ttl = TTL,
                data = {0,0,1024,Domain}
            };
        _ ->
            {err, fmt}
    end;

type({txt, L}) when is_list(L) ->
    Domain = proplists:get_value(domain, L, hostname()),
    Class = proplists:get_value(class, L, in), % should be cache flush
    TTL = proplists:get_value(ttl, L, ?TTL_LONG),
    Data = proplists:get_value(data, L, []),

    case Data of
        Any when is_list(Any) ->
            #dns_rr{
                domain = Domain,
                type = txt,
                class = Class,
                ttl = TTL,
                data = Data
            };
        _ ->
            {err, fmt}
    end;

type({a, L}) when is_list(L) ->
    Domain = proplists:get_value(domain, L, hostname()),
    Class = proplists:get_value(class, L, in),
    TTL = proplists:get_value(ttl, L, ?TTL_SHORT),
    {IP1,IP2,IP3,IP4} = proplists:get_value(data, L, local_address()),

    #dns_rr{
        domain = Domain,
        type = a,
        class = Class,
        ttl = TTL,
        data = <<IP1,IP2,IP3,IP4>>
    };

type({any, L}) when is_list(L) ->
    Domain = proplists:get_value(domain, L, hostname()),
    Class = proplists:get_value(class, L, in),
    TTL = proplists:get_value(ttl, L, ?TTL_SHORT),

    #dns_rr{
        domain = Domain,
        type = any,
        class = Class,
        ttl = TTL
    }.


encode(L) when is_list(L) ->
    Header = proplists:get_value(header, L, type(header)),
    Queries = proplists:get_value(queries, L, []),
    Answers = proplists:get_value(answers, L, []),
    Resources = proplists:get_value(resources, L, []),

    Record = #dns_rec{
        header = Header,
        qdlist = Queries,
        anlist = Answers,
        arlist = Resources
    },
    inet_dns:encode(Record).


%%%
%%% Services
%%%
service(probe) ->
    Any = type({any, [{class, ?CLASS_CF}]}),
    encode([{answers, [Any]}]);

service(host) ->
    A = type({a, [{class, ?CLASS_CF}]}),
    encode([{answers, [A]}]);

% See:
% http://dacp.jsharkey.org/
% http://blog.mycroes.nl/2008/08/pairing-itunes-remote-app-with-your-own.html
service(daap) ->
    Service = "0000000000000000000000000000000000000011._touch-remote._tcp.local",
    Hostname = hostname(),
    IP = local_address(),

    PTR = type({ptr, [
                {domain, "_touch-remote._tcp.local"},
                {ttl, ?TTL_LONG},
                {data, Service}
            ]}),

    TXT = type({txt, [
                {domain, Service},
                {ttl, 4500},
                {data, [
                        "DvNm=erlMOTE",
                        "RemV=10000",
                        "DvTy=iPod",
                        "RemN=Remote",
                        "txtvers=1",
                        "Pair=0000000000000011"
                    ]}
            ]}), 

    SRV = type({srv, [
                {domain, Service},
                {data,  {0,0,1024,Hostname}} % XXX should allow setting port
            ]}),

    A = type({a, [
                {domain, Hostname},
                {class, ?CLASS_CF},
                {data, IP}
            ]}),

    encode([{answers, [PTR, TXT, SRV, A]}]).


%%
%% Utilities
%%

reverse_address(Addr) when is_tuple(Addr) ->
    % 212.213.168.192.in-addr.arpa
    lists:flatten([ integer_to_list(N) ++ "." ||
            N <- lists:reverse(tuple_to_list(Addr)) ]
        ++ "in-addr.arpa").


%%
%% Defaults
%%

hostname() ->
    % inet:gethostname/0 will never fail
    hd(string:tokens(element(2,inet:gethostname()), ".")) ++ ".local".

local_address() ->
    Host = element(2, inet:gethostname()),
    {ok, HE} = inet:gethostbyname(Host),
    hd(HE#hostent.h_addr_list).


