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
-define(DEFAULT_POSTS, "./posts/").
-define(POST_ID_BYTE_SIZE, 32).
-define(POST_BYTE_SIZE_LIMIT, 4*1024).
-define(CHALLENGE_TIMEOUT, 60*1000).
-define(CHALLENGE_BYTE_SIZE, 32).
-define(CHALLENGE_LEADING_ZEROS, 5).

%% TODO: Limit the amount of connections from a single IP.

-spec start() -> pid().
start() ->
    start(?DEFAULT_PORT, ?DEFAULT_POSTS).

-spec start(Port, Posts) -> pid() when
      Port :: inet:port_number(),
      Posts :: file:name_all().
start(Port, Posts) ->
    %% ok = filelib:ensure_dir(Posts),
    Options = [binary, {packet, line}, {active, false}, {reuseaddr, true}],
    Server = spawn(fun () -> server(Posts) end),
    {ok, LSock} = gen_tcp:listen(Port, Options),
    %% TODO: the accepter should be created and monitored by the server
    _IgnoringAccepter = spawn(fun () -> accepter(LSock, Server) end),
    Server.

-spec server(Posts) -> no_return() when
      Posts :: file:name_all().
server(Posts) ->
    receive
        {connected, Sock} ->
            {ok, Addr} = inet:peername(Sock),
            {Pid, _Ref} = spawn_monitor(fun () -> session(command, Sock, Addr, Posts) end),
            put(Pid, {Sock, Addr});
        {'DOWN', _Ref, process, Pid, Reason} ->
            case get(Pid) of
                {Sock, Addr} ->
                    case Reason of
                        normal ->
                            io:format("~p: exited normally\n", [Addr]);
                        Reason ->
                            io:format("~p: ERROR: exited with reason: ~p\n", [Addr, Reason]),
                            gen_tcp:send(Sock, <<"500\r\n">>)
                    end,
                    gen_tcp:close(Sock),
                    erase(Pid);
                undefined ->
                    io:format("WARNING: process ~p went down, but it was not associated with any sockets. Weird...\n", [Pid])
            end;
        Message ->
            io:format("WARNING: Unknown message ~p\n", [Message])
    end,
    server(Posts).

-type addr() :: {inet:ip_address(), inet:port_number()} |
                inet:returned_non_ip_address().

-type session_state() :: command |
                         {challenge, binary()} |
                         {accepted, binary(), binary()} |
                         {post, binary()} |
                         {get, unicode:chardata()}.

-spec session(State, Sock, Addr, Posts) -> ok when
      State :: session_state(),
      Sock  :: gen_tcp:socket(),
      Addr  :: addr(),
      Posts :: file:name_all().
session(command, Sock, Addr, Posts) ->
    gen_tcp:send(Sock, <<"HI\r\n">>),
    io:format("~p: connected\n", [Addr]),
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"CRASH\r\n">>} ->
            throw(crash);
        {ok, <<"POST\r\n">>} ->
            gen_tcp:send(Sock, <<"OK\r\n">>),
            io:format("~p: wants to make a post\n", [Addr]),
            session({post, <<"">>}, Sock, Addr, Posts);
        {ok, <<"GET ", Id/binary>>} ->
            io:format("~p: wants to get a post\n", [Addr]),
            session({get, string:trim(Id)}, Sock, Addr, Posts);
        {ok, Command} ->
            io:format("~p: ERROR: invalid command: ~p\n", [Addr, Command]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            ok;
        {error, Reason} ->
            exit(Reason)
    end;
session({post, Content}, Sock, Addr, Posts) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"SUBMIT\r\n">>} ->
            io:format("~p: submitted the post of size ~p bytes\n", [Addr, byte_size(Content)]),
            session({challenge, Content}, Sock, Addr, Posts);
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
                                    session({post, <<Content/binary, Line/binary>>}, Sock, Addr, Posts)
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
session({challenge, Content}, Sock, Addr, Posts) ->
    Challenge = base64:encode(crypto:strong_rand_bytes(?CHALLENGE_BYTE_SIZE)),
    gen_tcp:send(Sock, io_lib:bformat(<<"CHALLENGE sha256 ~p ~ts\r\n">>, [?CHALLENGE_LEADING_ZEROS, Challenge])),
    io:format("~p: has been challenged with prefix ~ts\n", [Addr, Challenge]),
    session({accepted, Content, Challenge}, Sock, Addr, Posts);
session({accepted, Content, Challenge}, Sock, Addr, Posts) ->
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
                    PostPath = io_lib:format("~ts/~ts", [Posts, Id]),
                    %% TODO: try to regenerate the Id several times until you find the one that is not taken
                    case filelib:is_regular(PostPath) of
                        false ->
                            ok = file:write_file(PostPath, Content),
                            gen_tcp:send(Sock, [<<"SENT ">>, Id, <<"\r\n">>]),
                            ok;
                        true ->
                            %% Very unlikely to happen, but still
                            gen_tcp:send(Sock, [<<"500\r\n">>]),
                            ok
                    end;
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
session({get, Id}, Sock, Addr, Posts) ->
    case is_valid_post_id(Id) of
        true ->
            %% PostPath is safe to log with ~ts since it's made out of
            %% Posts which we trust and Id which is verified with
            %% is_valid_post_id/1.
            PostPath = io_lib:format("~ts/~ts", [Posts, Id]),
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

%% TODO: delete the posts by requiring the user to provide the CHALLENGE and ACCEPTED strings.
%% TODO: maybe post ids should be uuids?
%% TODO: Protocol versioning. The server may announce the version it supports in the "HI\r\n".
%% TODO: Some sort of heartbeat mechanism while the client is doing POW challenge.
%% TODO: Should we support TLS connections?
