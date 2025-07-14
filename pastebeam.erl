-module(pastebeam).
-export([start/0, accepter/1, session/2]).

%% TODO: use prefix challenge instead of suffix
%% TODO: protocol versioning
%% TODO: limit the size of the uploaded file
%% TODO: flexible challenge
%% TODO: limit the allowed charset in the submitted documents

start() ->
    {ok, LSock} = gen_tcp:listen(6969, [binary, {packet, line}, {active, false}, {reuseaddr, true}]),
    spawn(?MODULE, accepter, [LSock]).

fail_session(Sock, Reason) ->
    io:format("ERROR: session failed: ~w\n", [Reason]),
    gen_tcp:close(Sock),
    ok.

-spec session(State, Sock) -> ok when
      State :: command |
               {challenge, binary()} |
               {accepted, binary(), binary()} |
               {post, binary()} |
               {get, unicode:chardata()},
      Sock :: gen_tcp:socket().
session(command, Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"POST\r\n">>} ->
            session({post, <<"">>}, Sock);
        {ok, <<"GET ", Id/binary>>} ->
            session({get, string:trim(Id)}, Sock);
        {ok, Command} ->
            io:format("ERROR: invalid command: ~w\n", [Command]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            gen_tcp:close(Sock),
            ok;
        {error, Reason} ->
            fail_session(Sock, Reason)
    end;
session({post, Lines}, Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"SUBMIT\r\n">>} ->
            session({challenge, Lines}, Sock);
        {ok, Line} ->
            session({post, <<Lines/binary, Line/binary>>}, Sock);
        {error, Reason} ->
            fail_session(Sock, Reason)
    end;
session({challenge, Lines}, Sock) ->
    Challenge = binary:encode_hex(crypto:strong_rand_bytes(32)),
    gen_tcp:send(Sock, [<<"CHALLENGE ">>, Challenge, <<"\r\n">>]),
    session({accepted, Lines, Challenge}, Sock);
session({accepted, Lines, Challenge}, Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"ACCEPTED ", Suffix/binary>>} ->
            Blob = <<Lines/binary, Challenge/binary, <<"\r\n">>/binary, Suffix/binary>>,
            io:format("BLOB: ~w\n", [Blob]),
            case binary:encode_hex(crypto:hash(sha256, Blob)) of
                <<"00000", _/binary>> ->
                    Id = binary:encode_hex(crypto:strong_rand_bytes(32)),
                    %% TODO: Save to a separate folder
                    file:write_file(Id, Lines),
                    gen_tcp:send(Sock, [<<"SENT ">>, Id, <<"\r\n">>]),
                    gen_tcp:close(Sock),
                    ok;
                Hash ->
                    io:format("ERROR: challenge failed: ~s\n", [Hash]),
                    gen_tcp:send(Sock, <<"CHALLENGED FAILED\r\n">>),
                    gen_tcp:close(Sock),
                    ok
            end;
        {ok, _} ->
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            gen_tcp:close(Sock),
            ok;
        {error, Reason} ->
            fail_session(Sock, Reason)
    end;
session({get, Id}, Sock) ->
    io:format("TODO: GET ~s\n", [Id]),
    gen_tcp:close(Sock),
    ok.

accepter(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    spawn(?MODULE, session, [command, Sock]),
    accepter(LSock).
