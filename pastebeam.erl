-module(pastebeam).
-export([start/1, accepter/1, session/3]).

%% TODO: use prefix challenge instead of suffix
%% TODO: protocol versioning
%% TODO: limit the size of the uploaded file
%% TODO: flexible challenge
%% TODO: limit the allowed charset in the submitted documents
%% TODO: challenge timeout

-type addr() :: {inet:ip_address(), inet:port_number()} |
                inet:returned_non_ip_address().

-spec start(Port) -> pid() when
      Port :: inet:port_number().
start(Port) ->
    Options = [binary, {packet, line}, {active, false}, {reuseaddr, true}],
    {ok, LSock} = gen_tcp:listen(Port, Options),
    spawn(?MODULE, accepter, [LSock]).

-spec fail_session(Sock, Addr, Reason) -> ok when
      Addr :: addr,
      Sock :: gen_tcp:socket(),
      Reason :: term().
fail_session(Sock, Addr, Reason) ->
    io:format("~w: ERROR: session failed: ~w\n", [Addr, Reason]),
    gen_tcp:close(Sock),
    ok.

-spec session(State, Sock, Addr) -> ok when
      State :: command |
               {challenge, binary()} |
               {accepted, binary(), binary()} |
               {post, binary()} |
               {get, unicode:chardata()},
      Sock :: gen_tcp:socket(),
     Addr :: addr().
session(command, Sock, Addr) ->
    io:format("~w: connected\n", [Addr]),
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"POST\r\n">>} ->
            io:format("~w: wants to make a post\n", [Addr]),
            session({post, <<"">>}, Sock, Addr);
        {ok, <<"GET ", Id/binary>>} ->
            io:format("~w: wants to get a post by id ~w\n", [Addr, Id]),
            session({get, string:trim(Id)}, Sock, Addr);
        {ok, Command} ->
            io:format("~w: ERROR: invalid command: ~w\n", [Addr, Command]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            gen_tcp:close(Sock),
            ok;
        {error, Reason} ->
            fail_session(Sock, Addr, Reason)
    end;
session({post, Content}, Sock, Addr) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"SUBMIT\r\n">>} ->
            io:format("~w: submitted the post of the ~p bytes\n", [Addr, byte_size(Content)]),
            session({challenge, Content}, Sock, Addr);
        {ok, Line} ->
            session({post, <<Content/binary, Line/binary>>}, Sock, Addr);
        {error, Reason} ->
            fail_session(Sock, Addr, Reason)
    end;
session({challenge, Content}, Sock, Addr) ->
    Challenge = binary:encode_hex(crypto:strong_rand_bytes(32)),
    gen_tcp:send(Sock, [<<"CHALLENGE ">>, Challenge, <<"\r\n">>]),
    io:format("~w: has been challenged\n", [Addr]),
    session({accepted, Content, Challenge}, Sock, Addr);
session({accepted, Content, Challenge}, Sock, Addr) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"ACCEPTED ", Suffix/binary>>} ->
            io:format("~w: accepted the challenge\n", [Addr]),
            Blob = <<Content/binary,
                     Challenge/binary,
                     <<"\r\n">>/binary,
                     Suffix/binary>>,
            case binary:encode_hex(crypto:hash(sha256, Blob)) of
                <<"00000", _/binary>> ->
                    Id = binary:encode_hex(crypto:strong_rand_bytes(32)),
                    io:format("~w: completed the challenge: Id: ~w\n", [Addr, Id]),
                    %% TODO: create the ./posts/ folder if does not exists
                    %% TODO: customizable ./posts/ folder
                    ok = file:write_file(<<"./posts/", Id/binary>>, Content),
                    gen_tcp:send(Sock, [<<"SENT ">>, Id, <<"\r\n">>]),
                    gen_tcp:close(Sock),
                    ok;
                Hash ->
                    io:format("~w: ERROR: failed the challenge: Hash: ~w\n", [Addr, Hash]),
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
session({get, Id}, Sock, Addr) ->
    io:format("~w: TODO: GET ~w\n", [Addr, Id]),
    gen_tcp:close(Sock),
    ok.

-spec accepter(LSock) -> no_return() when
      LSock :: gen_tcp:socket().
accepter(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    {ok, Addr} = inet:peername(Sock),
    spawn(?MODULE, session, [command, Sock, Addr]),
    accepter(LSock).
