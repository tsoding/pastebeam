%% # PasteBEAM Service
%%
%% Reference implementation.
%%
%% ## Logging Notes
%%
%% We are currently logging with just io:format for the sake of
%% simplicity.
%%
%% Potentially dangerous data for ANSI Terminals should be formatted
%% with ~p. Safe human readable strings should be probably formatted
%% with ~ts.
-module(pastebeam).
-export([start/0, start/2]).

-define(DEFAULT_PORT, 6969).
-define(DEFAULT_POSTS_ROOT, "./posts/").
-define(POST_ID_BYTE_SIZE, 32).
-define(POST_BYTE_SIZE_LIMIT, 4*1024).
-define(CHALLENGE_TIMEOUT, 60*1000).
-define(CHALLENGE_BYTE_SIZE, 32).
-define(CHALLENGE_LEADING_ZEROS, 5).
-define(MAX_LIMIT_PER_IP, 10).

-spec start() -> pid().
start() ->
    start(?DEFAULT_PORT, ?DEFAULT_POSTS_ROOT).

-spec start(Port, PostsRoot) -> pid() when
      Port :: inet:port_number(),
      PostsRoot :: file:name_all().
start(Port, PostsRoot) ->
    ok = filelib:ensure_dir(PostsRoot),
    Options = [binary, {packet, line}, {active, false}, {reuseaddr, true}],
    Server = spawn(fun () -> server(PostsRoot, #{}, #{}) end),
    {ok, LSock} = gen_tcp:listen(Port, Options),
    %% TODO: the accepter should be created and monitored by the server
    _IgnoringAccepter = spawn(fun () -> accepter(LSock, Server) end),
    Server.

-spec server(PostsRoot, Connections, Limits) -> no_return() when
      PostsRoot   :: file:name_all(),
      Connections :: #{ Pid :: pid() => {Socket :: gen_tcp:socket(), Addr :: addr()} },
      Limits      :: #{ IP :: term() => integer() }.
server(PostsRoot, Connections, Limits) ->
    receive
        {connected, Sock} ->
            case inet:peername(Sock) of
                {ok, Addr} ->
                    {IP, _Port} = Addr,
                    Limit = maps:get(IP, Limits, 0) + 1,
                    if
                        Limit > ?MAX_LIMIT_PER_IP ->
                            io:format("~p: ERROR: too many connections\n", [Addr]),
                            gen_tcp:send(Sock, <<"TOO MANY CONNECTIONS\r\n">>),
                            gen_tcp:close(Sock),
                            server(PostsRoot, Connections, Limits);
                        true ->
                            NewLimits = maps:put(IP, Limit, Limits),
                            {Pid, _Ref} = spawn_monitor(fun () -> session(command, Sock, Addr, PostsRoot) end),
                            NewConnections = maps:put(Pid, {Sock, Addr}, Connections),
                            server(PostsRoot, NewConnections, NewLimits)
                    end;
                {error, Posix} ->
                    io:format("ERROR: could not get a remote address of a connection: ~p\n", [Posix]),
                    server(PostsRoot, Connections, Limits)
            end;
        {'DOWN', _Ref, process, Pid, Reason} ->
            case maps:get(Pid, Connections, undefined) of
                {Sock, Addr} ->
                    case Reason of
                        normal ->
                            io:format("~p: exited normally\n", [Addr]);
                        Reason ->
                            io:format("~p: ERROR: exited with reason: ~p\n", [Addr, Reason]),
                            gen_tcp:send(Sock, <<"500\r\n">>)
                    end,
                    gen_tcp:close(Sock),
                    NewConnections = maps:remove(Pid, Connections),
                    {IP, _Port} = Addr,
                    Limit = case maps:get(IP, Limits, 0) of
                                Value when Value > 0  -> Value - 1;
                                Value -> Value
                            end,
                    NewLimits = maps:put(IP, Limit, Limits),
                    server(PostsRoot, NewConnections, NewLimits);
                undefined ->
                    io:format("WARNING: process ~p went down, but it was not associated with any sockets. Weird...\n", [Pid]),
                    server(PostsRoot, Connections, Limits)
            end;
        Message ->
            io:format("WARNING: Unknown message ~p\n", [Message]),
            server(PostsRoot, Connections, Limits)
    end.

-type addr() :: {inet:ip_address(), inet:port_number()} |
                inet:returned_non_ip_address().

-type session_state() :: command |
                         {challenge, binary()} |
                         {accepted, binary(), binary()} |
                         {post, binary()} |
                         {get, unicode:chardata()}.

-spec session(State, Sock, Addr, PostsRoot) -> ok when
      State :: session_state(),
      Sock  :: gen_tcp:socket(),
      Addr  :: addr(),
      PostsRoot :: file:name_all().
session(command, Sock, Addr, PostsRoot) ->
    gen_tcp:send(Sock, <<"HI\r\n">>),
    io:format("~p: connected\n", [Addr]),
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"CRASH\r\n">>} ->
            throw(crash);
        {ok, <<"POST\r\n">>} ->
            gen_tcp:send(Sock, <<"OK\r\n">>),
            io:format("~p: wants to make a post\n", [Addr]),
            session({post, <<"">>}, Sock, Addr, PostsRoot);
        {ok, <<"GET ", Id/binary>>} ->
            io:format("~p: wants to get a post\n", [Addr]),
            session({get, string:trim(Id)}, Sock, Addr, PostsRoot);
        {ok, Command} ->
            io:format("~p: ERROR: invalid command: ~p\n", [Addr, Command]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            ok;
        {error, Reason} ->
            exit(Reason)
    end;
session({post, Content}, Sock, Addr, PostsRoot) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"SUBMIT\r\n">>} ->
            io:format("~p: submitted the post of size ~p bytes\n", [Addr, byte_size(Content)]),
            session({challenge, Content}, Sock, Addr, PostsRoot);
        {ok, Line} ->
            %% Is line a valid UTF-8?
            case unicode:characters_to_list(Line, utf8) of
                {error, _, _}  ->
                    io:format("~p: ERROR: invalid utf8\n", [Addr]),
                    gen_tcp:send(Sock, <<"INVALID UTF8\r\n">>),
                    ok;
                {incomplete, _, _} ->
                    io:format("~p: ERROR: incomplete utf8\n", [Addr]),
                    gen_tcp:send(Sock, <<"INVALID UTF8\r\n">>), % For the user it's all invalid utf8, no distinction
                    ok;
                _Line ->
                    %% Does the line end with \r\n?
                    case binary:longest_common_suffix([Line, <<"\r\n">>]) of
                        2 ->
                            %% Does the line overflow the post size limit?
                            PostSize = byte_size(Content) + byte_size(Line),
                            if
                                PostSize >= ?POST_BYTE_SIZE_LIMIT ->
                                    io:format("~p: ERROR: post is too big\n", [Addr]),
                                    gen_tcp:send(Sock, <<"TOO BIG\r\n">>),
                                    ok;
                                true ->
                                    %% All good, adding the line
                                    gen_tcp:send(Sock, <<"OK\r\n">>),
                                    session({post, <<Content/binary, Line/binary>>}, Sock, Addr, PostsRoot)
                            end;
                        _ ->
                            io:format("~p: ERROR: bad line ending\n", [Addr]),
                            gen_tcp:send(Sock, <<"BAD LINE ENDING\r\n">>),
                            ok
                    end
            end;
        {error, Reason} ->
            exit(Reason)
    end;
session({challenge, Content}, Sock, Addr, PostsRoot) ->
    Challenge = base64:encode(crypto:strong_rand_bytes(?CHALLENGE_BYTE_SIZE)),
    gen_tcp:send(Sock, io_lib:bformat(<<"CHALLENGE sha256 ~p ~ts\r\n">>, [?CHALLENGE_LEADING_ZEROS, Challenge])),
    io:format("~p: has been challenged with prefix ~ts\n", [Addr, Challenge]),
    session({accepted, Content, Challenge}, Sock, Addr, PostsRoot);
session({accepted, Content, Challenge}, Sock, Addr, PostsRoot) ->
    case gen_tcp:recv(Sock, 0, ?CHALLENGE_TIMEOUT) of
        {ok, <<"ACCEPTED ", Prefix/binary>>} ->
            io:format("~p: accepted the challenge\n", [Addr]),
            Blob = <<Prefix/binary,
                     Content/binary,
                     Challenge/binary,
                     <<"\r\n">>/binary>>,
            Hash = binary:encode_hex(crypto:hash(sha256, Blob)),
            LeadingZeros = count_leading_zeros(Hash),
            if
                LeadingZeros >= ?CHALLENGE_LEADING_ZEROS ->
                    io:format("~p: completed the challenge with hash: ~ts\n", [Addr, Hash]),
                    Id = random_valid_post_id(),
                    io:format("~p: assigned post id: ~ts\n", [Addr, Id]),
                    PostPath = io_lib:format("~ts/~ts", [PostsRoot, Id]),
                    %% TODO: try to regenerate the Id several times until you find the one that is not taken
                    false = filelib:is_regular(PostPath), %% Very unlikely to happen, but still
                    ok    = file:write_file(PostPath, Content),
                    gen_tcp:send(Sock, [<<"SENT ">>, Id, <<"\r\n">>]),
                    ok;
                true ->
                    io:format("~p: ERROR: failed the challenge with hash: ~ts\n", [Addr, Hash]),
                    gen_tcp:send(Sock, <<"CHALLENGED FAILED\r\n">>),
                    ok
            end;
        {ok, _} ->
            io:format("~p: ERROR: failed the challenge: Invalid Command\n", [Addr]),
            gen_tcp:send(Sock, <<"INVALID COMMAND\r\n">>),
            ok;
        {error, timeout} ->
            io:format("~p: ERROR: failed the challenge: Timeout\n", [Addr]),
            gen_tcp:send(Sock, <<"TOO SLOW\r\n">>),
            ok;
        {error, Reason} ->
            exit(Reason)
    end;
session({get, Id}, Sock, Addr, PostsRoot) ->
    case is_valid_post_id(Id) of
        true ->
            %% PostPath is safe to log with ~ts since it's made out of
            %% PostsRoot which we trust and Id which is verified with
            %% is_valid_post_id/1.
            PostPath = io_lib:format("~ts/~ts", [PostsRoot, Id]),
            case file:read_file(PostPath) of
                {ok, Binary} ->
                    io:format("~p: sending out post ~ts\n", [Addr, PostPath]),
                    gen_tcp:send(Sock, Binary),
                    ok;
                {error, enoent} ->
                    io:format("~p: ERROR: could not read post file ~ts: doesn't exists\n", [Addr, PostPath]),
                    gen_tcp:send(Sock, <<"404\r\n">>),
                    ok;
                {error, Reason} ->
                    exit(Reason)
            end;
        false ->
            %% Id is invalid post ID submitted by user! Always log such things with ~p!
            io:format("~p: ERROR: invalid Post ID: ~p\n", [Addr, Id]),
            gen_tcp:send(Sock, <<"404\r\n">>), %% Do not let the user know that the id is invalid. It's all "not found" for them.
            ok
    end.

-spec random_valid_post_id() -> binary().
random_valid_post_id() ->
    binary:encode_hex(crypto:strong_rand_bytes(?POST_ID_BYTE_SIZE)).

-spec is_hex_digit(X :: integer()) -> boolean().
is_hex_digit(X) -> (($0 =< X) and (X =< $9)) or (($A =< X) and (X =< $F)).

-spec count_leading_zeros_impl(Digest :: binary(), Acc :: integer()) -> integer().
count_leading_zeros_impl(<<"0", Digest/binary>>, Acc) ->
    count_leading_zeros_impl(Digest, Acc + 1);
count_leading_zeros_impl(_Digest, Acc) ->
    Acc.

-spec count_leading_zeros(Digest :: binary()) -> integer().
count_leading_zeros(Digest) ->
    count_leading_zeros_impl(Digest, 0).

-spec is_valid_post_id(Id) -> boolean() when
      Id :: binary().
is_valid_post_id(Id) ->
    IdList = binary_to_list(Id),
    (length(IdList) == ?POST_ID_BYTE_SIZE*2) and lists:all(fun is_hex_digit/1, IdList).

-spec accepter(LSock, Server) -> no_return() when
      LSock :: gen_tcp:socket(),
      Server :: pid().
accepter(LSock, Server) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    Server ! {connected, Sock},
    accepter(LSock, Server).

%% TODO: Delete the posts by requiring the user to provide the CHALLENGE and ACCEPTED strings.
%% TODO: Maybe post ids should be uuids?
%% TODO: Some sort of heartbeat mechanism while the client is doing POW challenge.
%% TODO: Should we support TLS connections?
%% TODO: server process should support hot reloading itself by a message
%%   https://stackoverflow.com/a/11971978
%% TODO: dynamically increase the challenge as the load increases
