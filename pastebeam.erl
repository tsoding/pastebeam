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
-export([start/0, start/3, default_public_params/0]).

-define(DEFAULT_PORT, 6969).
-define(DEFAULT_POSTS_ROOT, "./posts/").
-define(POST_ID_BYTE_SIZE, 32).

-doc "Parameters of the server visible to the clients via PARAMS\r\n command".
-record(public_params, { challenge_leading_zeros :: integer(),
                         challenge_timeout_ms    :: timeout(),
                         challenge_byte_size     :: integer(),
                         max_limit_per_ip        :: integer(),
                         post_byte_size_limit    :: integer() }).

-spec default_public_params() -> #public_params {}.
default_public_params() ->
    #public_params { challenge_leading_zeros = 6,
                     challenge_timeout_ms    = 60*1000,
                     challenge_byte_size     = 32,
                     max_limit_per_ip        = 5,
                     post_byte_size_limit    = 4*1024 }.

-record(session_params, { public_params :: #public_params{},
                          sock          :: gen_tcp:socket(),
                          addr          :: addr(),
                          posts_root    :: file:name_all()}).

-spec start() -> pid().
start() ->
    start(?DEFAULT_PORT, ?DEFAULT_POSTS_ROOT, default_public_params()).

-spec start(Port, PostsRoot, PublicParams) -> pid() when
      Port         :: inet:port_number(),
      PostsRoot    :: file:name_all(),
      PublicParams :: #public_params{}.
start(Port, PostsRoot, PublicParams) ->
    ok = filelib:ensure_dir(PostsRoot),
    Options = [binary, {packet, line}, {active, false}, {reuseaddr, true}],
    Server = spawn(fun () -> server(PostsRoot, PublicParams, #{}, #{}) end),
    {ok, LSock} = gen_tcp:listen(Port, Options),
    %% TODO: the accepter should be created and monitored by the server
    _IgnoringAccepter = spawn(fun () -> accepter(LSock, Server) end),
    Server.

%% The only reason this is a macro is because record_info/2 is
%% absolutely dumb. It's some sort of compile time expression that
%% does not accept runtime parameters.
-define(RECORD_FIELD_INDICES(RecordName),
        lists:zip(
          record_info(fields, RecordName),
          lists:seq(2, record_info(size, RecordName)))).

-spec server(PostsRoot, PublicParams, Connections, Limits) -> no_return() when
      PostsRoot    :: file:name_all(),
      PublicParams :: #public_params{},
      Connections  :: #{ Pid :: pid() => {Socket :: gen_tcp:socket(), Addr :: addr()} },
      Limits       :: #{ IP :: term() => integer() }.
server(PostsRoot, PublicParams, Connections, Limits) ->
    #public_params{ max_limit_per_ip = MAX_LIMIT_PER_IP } = PublicParams,
    receive
        {public_params} ->
            io:format("INFO: ~p\n", [record_info(fields, public_params)]),
            server(PostsRoot, PublicParams, Connections, Limits);
        {public_params, Field} ->
            case proplists:get_value(Field, ?RECORD_FIELD_INDICES(public_params)) of
                undefined ->
                    io:format("ERROR: invalid public parameter ~p, avaliable parameters are ~p\n",
                              [Field, record_info(fields, public_params)]);
                Index ->
                    io:format("INFO: ~p\n", [{Field, element(Index, PublicParams)}])
            end,
            server(PostsRoot, PublicParams, Connections, Limits);
        {public_params, Field, Value} ->
            case proplists:get_value(Field, ?RECORD_FIELD_INDICES(public_params)) of
                undefined ->
                    io:format("ERROR: invalid public parameter ~p, avaliable parameters are ~p\n",
                              [Field, record_info(fields, public_params)]),
                    server(PostsRoot, PublicParams, Connections, Limits);
                Index ->
                    NewPublicParams = setelement(Index, PublicParams, Value),
                    NewPublicParamsPropList = lists:zip(
                          record_info(fields, public_params),
                          lists:nthtail(1, tuple_to_list(NewPublicParams))),
                    io:format("INFO: updated ~p: ~p\n", [Field, NewPublicParamsPropList]),
                    server(PostsRoot, NewPublicParams, Connections, Limits)
            end;
        {connected, Sock} ->
            case inet:peername(Sock) of
                {ok, Addr} ->
                    {IP, _Port} = Addr,
                    Limit = maps:get(IP, Limits, 0) + 1,
                    if
                        Limit > MAX_LIMIT_PER_IP ->
                            io:format("~p: ERROR: too many connections\n", [Addr]),
                            gen_tcp:send(Sock, <<"TOO MANY CONNECTIONS\r\n">>),
                            gen_tcp:close(Sock),
                            server(PostsRoot, PublicParams, Connections, Limits);
                        true ->
                            SessionParams = #session_params { sock = Sock,
                                                              addr = Addr,
                                                              public_params = PublicParams,
                                                              posts_root = PostsRoot },
                            {Pid, _Ref} = spawn_monitor(fun () -> session(command, SessionParams) end),
                            NewLimits = maps:put(IP, Limit, Limits),
                            NewConnections = maps:put(Pid, {Sock, Addr}, Connections),
                            server(PostsRoot, PublicParams, NewConnections, NewLimits)
                    end;
                {error, Posix} ->
                    io:format("ERROR: could not get a remote address of a connection: ~p\n", [Posix]),
                    server(PostsRoot, PublicParams, Connections, Limits)
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
                    server(PostsRoot, PublicParams, NewConnections, NewLimits);
                undefined ->
                    io:format("WARNING: process ~p went down, but it was not associated with any sockets. Weird...\n", [Pid]),
                    server(PostsRoot, PublicParams, Connections, Limits)
            end;
        Message ->
            io:format("WARNING: Unknown message ~p\n", [Message]),
            server(PostsRoot, PublicParams, Connections, Limits)
    end.

-type addr() :: {inet:ip_address(), inet:port_number()} |
                inet:returned_non_ip_address().

-type session_state() :: command |
                         {challenge, Content :: binary()} |
                         {accepted, Content :: binary(), Challenge :: binary()} |
                         {post, Content :: binary()} |
                         {get, Id :: unicode:chardata()}.

-spec session(State, Params) -> ok when
      State   :: session_state(),
      Params  :: #session_params{}.
session(command, Params) ->
    #session_params { sock = Sock, addr = Addr, public_params = PublicParams } = Params,
    gen_tcp:send(Sock, <<"HI\r\n">>),
    io:format("~p: connected\n", [Addr]),
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"CRASH\r\n">>} ->
            throw(crash);
        {ok, <<"PARAMS\r\n">>} ->
            gen_tcp:send(Sock, io_lib:bformat(<<"CHALLENGE_LEADING_ZEROS ~p\r\n",
                                                "CHALLENGE_TIMEOUT_MS    ~p\r\n",
                                                "CHALLENGE_BYTE_SIZE     ~p\r\n",
                                                "MAX_LIMIT_PER_IP        ~p\r\n",
                                                "POST_BYTE_SIZE_LIMIT    ~p\r\n">>,
                                              [PublicParams#public_params.challenge_leading_zeros,
                                               PublicParams#public_params.challenge_timeout_ms,
                                               PublicParams#public_params.challenge_byte_size,
                                               PublicParams#public_params.max_limit_per_ip,
                                               PublicParams#public_params.post_byte_size_limit])),
            ok;
        {ok, <<"POST\r\n">>} ->
            gen_tcp:send(Sock, <<"OK\r\n">>),
            io:format("~p: wants to make a post\n", [Addr]),
            session({post, <<"">>}, Params);
        {ok, <<"GET ", Id/binary>>} ->
            io:format("~p: wants to get a post\n", [Addr]),
            session({get, string:trim(Id)}, Params);
        {ok, Command} ->
            io:format("~p: ERROR: invalid command: ~p\n", [Addr, Command]),
            gen_tcp:send(Sock, "INVALID COMMAND\r\n"),
            ok;
        {error, Reason} ->
            exit(Reason)
    end;
session({post, Content}, Params) ->
    #session_params { sock = Sock, addr = Addr, public_params = PublicParams } = Params,
    #public_params { post_byte_size_limit = POST_BYTE_SIZE_LIMIT } = PublicParams,
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"SUBMIT\r\n">>} ->
            io:format("~p: submitted the post of size ~p bytes\n", [Addr, byte_size(Content)]),
            session({challenge, Content}, Params);
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
                                PostSize >= POST_BYTE_SIZE_LIMIT ->
                                    io:format("~p: ERROR: post is too big\n", [Addr]),
                                    gen_tcp:send(Sock, <<"TOO BIG\r\n">>),
                                    ok;
                                true ->
                                    %% All good, adding the line
                                    gen_tcp:send(Sock, <<"OK\r\n">>),
                                    session({post, <<Content/binary, Line/binary>>}, Params)
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
session({challenge, Content}, Params) ->
    #session_params { addr = Addr, sock = Sock, public_params = PublicParams } = Params,
    #public_params { challenge_byte_size = CHALLENGE_BYTE_SIZE,
                     challenge_leading_zeros = CHALLENGE_LEADING_ZEROS } = PublicParams,
    Challenge = base64:encode(crypto:strong_rand_bytes(CHALLENGE_BYTE_SIZE)),
    gen_tcp:send(Sock, io_lib:bformat(<<"CHALLENGE sha256 ~p ~ts\r\n">>, [CHALLENGE_LEADING_ZEROS, Challenge])),
    io:format("~p: has been challenged with prefix ~ts\n", [Addr, Challenge]),
    session({accepted, Content, Challenge}, Params);
session({accepted, Content, Challenge}, Params) ->
    #session_params { addr          = Addr,
                      sock          = Sock,
                      posts_root    = PostsRoot,
                      public_params = PublicParams } = Params,
    #public_params { challenge_timeout_ms    = CHALLENGE_TIMEOUT_MS,
                     challenge_leading_zeros = CHALLENGE_LEADING_ZEROS} = PublicParams,
    case gen_tcp:recv(Sock, 0, CHALLENGE_TIMEOUT_MS) of
        {ok, <<"ACCEPTED ", Prefix/binary>>} ->
            io:format("~p: accepted the challenge\n", [Addr]),
            Blob = <<Prefix/binary,
                     Content/binary,
                     Challenge/binary,
                     <<"\r\n">>/binary>>,
            Hash = binary:encode_hex(crypto:hash(sha256, Blob)),
            LeadingZeros = count_leading_zeros(Hash),
            if
                LeadingZeros >= CHALLENGE_LEADING_ZEROS ->
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
session({get, Id}, Params) ->
    #session_params { addr = Addr, sock = Sock, posts_root = PostsRoot } = Params,
    case is_valid_post_id(Id) of
        true ->
            %% PostPath is safe to log with ~ts since it's made out of
            %% PublicParams#params.posts_root which we trust and Id which is verified with
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

-spec count_leading_zeros(Digest :: binary(), Acc :: integer()) -> integer().
count_leading_zeros(<<"0", Digest/binary>>, Acc) ->
    count_leading_zeros(Digest, Acc + 1);
count_leading_zeros(_Digest, Acc) ->
    Acc.

-spec count_leading_zeros(Digest :: binary()) -> integer().
count_leading_zeros(Digest) ->
    count_leading_zeros(Digest, 0).

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
