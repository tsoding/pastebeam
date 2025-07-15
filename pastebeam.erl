-module(pastebeam).
-export([start/0, start/2, accepter/2, session/4]).

-define(DEFAULT_PORT, 6969).
-define(DEFAULT_POSTS, "./posts/").

%% TODO: protocol versioning
%% TODO: limit the size of the uploaded file
%% TODO: flexible challenge
%% TODO: limit the allowed charset in the submitted documents
%% TODO: challenge timeout

-type addr() :: {inet:ip_address(), inet:port_number()} |
                inet:returned_non_ip_address().

-spec start() -> pid().
start() ->
    start(?DEFAULT_PORT, ?DEFAULT_POSTS).

-spec start(Port, Posts) -> pid() when
      Port :: inet:port_number(),
      Posts :: file:name_all().
start(Port, Posts) ->
    ok = filelib:ensure_dir(Posts),
    Options = [binary, {packet, line}, {active, false}, {reuseaddr, true}],
    {ok, LSock} = gen_tcp:listen(Port, Options),
    spawn(fun () -> accepter(LSock, Posts) end).

-spec fail_session(Sock, Addr, Reason) -> ok when
      Addr :: addr,
      Sock :: gen_tcp:socket(),
      Reason :: term().
fail_session(Sock, Addr, Reason) ->
    io:format("~w: ERROR: session failed: ~w\n", [Addr, Reason]),
    gen_tcp:close(Sock),
    ok.

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
    io:format("~w: connected\n", [Addr]),
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"POST\r\n">>} ->
            io:format("~w: wants to make a post\n", [Addr]),
            session({post, <<"">>}, Sock, Addr, Posts);
        {ok, <<"GET ", Id/binary>>} ->
            io:format("~w: wants to get a post by id ~w\n", [Addr, Id]),
            session({get, string:trim(Id)}, Sock, Addr, Posts);
        {ok, Command} ->
            io:format("~w: ERROR: invalid command: ~w\n", [Addr, Command]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            gen_tcp:close(Sock),
            ok;
        {error, Reason} ->
            fail_session(Sock, Addr, Reason)
    end;
session({post, Content}, Sock, Addr, Posts) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"SUBMIT\r\n">>} ->
            io:format("~w: submitted the post of the ~p bytes\n", [Addr, byte_size(Content)]),
            session({challenge, Content}, Sock, Addr, Posts);
        {ok, Line} ->
            session({post, <<Content/binary, Line/binary>>}, Sock, Addr, Posts);
        {error, Reason} ->
            fail_session(Sock, Addr, Reason)
    end;
session({challenge, Content}, Sock, Addr, Posts) ->
    Challenge = binary:encode_hex(crypto:strong_rand_bytes(32)),
    gen_tcp:send(Sock, [<<"CHALLENGE ">>, Challenge, <<"\r\n">>]),
    io:format("~w: has been challenged\n", [Addr]),
    session({accepted, Content, Challenge}, Sock, Addr, Posts);
session({accepted, Content, Challenge}, Sock, Addr, Posts) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"ACCEPTED ", Prefix/binary>>} ->
            io:format("~w: accepted the challenge\n", [Addr]),
            Blob = <<Prefix/binary,
                     Content/binary,
                     Challenge/binary,
                     <<"\r\n">>/binary>>,
            case binary:encode_hex(crypto:hash(sha256, Blob)) of
                <<"00000", _/binary>> ->
                    Id = binary:encode_hex(crypto:strong_rand_bytes(32)),
                    io:format("~w: completed the challenge: Id: ~ts\n", [Addr, Id]),
                    PostPath = io_lib:format("~ts/~ts", [Posts, Id]),
                    ok = file:write_file(PostPath, Content),
                    gen_tcp:send(Sock, [<<"SENT ">>, Id, <<"\r\n">>]),
                    gen_tcp:close(Sock),
                    ok;
                Hash ->
                    io:format("~w: ERROR: failed the challenge: Hash: ~ts\n", [Addr, Hash]),
                    gen_tcp:send(Sock, <<"CHALLENGED FAILED\r\n">>),
                    gen_tcp:close(Sock),
                    ok
            end;
        {ok, _} ->
            io:format("~w: ERROR: failed the challenge: Invalid Command\n", [Addr]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            gen_tcp:close(Sock),
            ok;
        {error, Reason} ->
            fail_session(Sock, Addr, Reason)
    end;
session({get, Id}, Sock, Addr, _Posts) ->
    io:format("~w: TODO: GET ~w\n", [Addr, Id]),
    gen_tcp:close(Sock),
    ok.

-spec accepter(LSock, Posts) -> no_return() when
      LSock :: gen_tcp:socket(),
      Posts :: file:name_all().
accepter(LSock, Posts) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    {ok, Addr} = inet:peername(Sock),
    spawn(fun () -> session(command, Sock, Addr, Posts) end),
    accepter(LSock, Posts).
