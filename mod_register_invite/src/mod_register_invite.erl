%%%---------------------------------------------------------------------
%%% @doc  Invite‑only in‑band registration for ejabberd
%%%---------------------------------------------------------------------
-module(mod_register_invite).
-behaviour(gen_mod).
-include_lib("ejabberd/include/logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").

%% API callbacks -------------------------------------------------------
-export([
    start/2,
    stop/1,
    depends/2,
    mod_options/1,
    mod_opt_type/1,
    mod_doc/0
]).

%% Hook callbacks ------------------------------------------------------
-export([
    check_token/3,
    adhoc_local_items/4,
    adhoc_local_commands/4,
    on_vcard_get/2,
    on_invite_message/1,
    validate_and_decrement/1,
    peek_token/1,
    handle_iq/2,
    cleanup_expired_tokens/1
]).


-record(invite_token, {
    token      :: binary(),
    host       :: binary(),
    expiry     :: integer(),   %% epoch seconds
    uses_left  :: integer()
}).

%%%===================================================================
%%% Lifecycle
%%%===================================================================

start(Host, Opts) ->
  ?INFO_MSG("Starting mod_register_invite on ~p with options: ~p", [Host, Opts]),
  %% Check if table exists first, then check attributes if it does
  Tables = mnesia:system_info(tables),
  case lists:member(invite_token, Tables) of
    true ->
      case mnesia:table_info(invite_token, attributes) of
        ['token','host','expiry','uses_left'] ->
          ok;
        _ ->
          %% Table exists but has wrong structure, recreate it
          mnesia:delete_table(invite_token),
          create_invite_token_table()
      end;
    false ->
      %% Table doesn't exist, create it
      create_invite_token_table()
  end,

  %% Rest of initialization...
  ejabberd_hooks:add(pre_registration,     Host, ?MODULE, check_token,          80),
  ejabberd_hooks:add(adhoc_local_items,    Host, ?MODULE, adhoc_local_items,    50),
  ejabberd_hooks:add(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 50),
  Result = ejabberd_hooks:add(user_send_packet, Host, ?MODULE, on_invite_message, 10),
  gen_iq_handler:add_iq_handler(ejabberd_local, Host, ?NS_VCARD, ?MODULE, handle_iq, no_queue),
  %% Debugging Feedback.
  ?INFO_MSG("mod_register_invite: Hook loaded: ~p",[Result]),

  %% Clean-up old tokens:
  MaxTokenAge = 30 * 86400,   %% 30 days in seconds
  cleanup_expired_tokens(MaxTokenAge),

  ok.

%% Helper function to create the table
create_invite_token_table() ->
  mnesia:create_table(invite_token, [
    {attributes, record_info(fields, invite_token)},
    {disc_copies, [node()]},
    {type, set}
  ]).

stop(Host) ->
  ejabberd_hooks:delete(pre_registration,     Host, ?MODULE, check_token,          80),
  ejabberd_hooks:delete(adhoc_local_items,    Host, ?MODULE, adhoc_local_items,    50),
  ejabberd_hooks:delete(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 50),
  ejabberd_hooks:delete(iq,               Host, ?MODULE, handle_iq,         100),
  ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, on_invite_message, 10),
  gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_VCARD),
ok.

depends(_Host, _Opts) ->
    [{mod_adhoc, hard}].

%%%-------------------------------------------------------------------
mod_options(Host) ->
    DefaultBase = <<"https://", Host/binary, "/register/new">>,
    [{token_lifetime, 86400},    %% seconds
     {default_uses,  1},
     {invite_base_url, DefaultBase}
    ].

mod_opt_type(token_lifetime)  -> econf:pos_int();
mod_opt_type(default_uses)    -> econf:pos_int();
mod_opt_type(invite_base_url) -> econf:string();
mod_opt_type(_)               -> [token_lifetime, default_uses, invite_base_url].

mod_doc() ->
    "Invite-only registration with expiring tokens".

%%%===================================================================
%%% Token Cleanup
%%%===================================================================

cleanup_expired_tokens(MaxAgeSeconds) ->
    ?INFO_MSG("Starting cleanup of expired tokens", []),
    Now = erlang:system_time(second),
    MaxAge = Now - MaxAgeSeconds,

    F = fun() ->
        %% Find tokens that are expired or have no uses left
        Tokens = mnesia:select(
            invite_token,
            [{#invite_token{token = '$1', host = '$2', expiry = '$3', uses_left = '$4'},
              [{'or',
                {'=<', '$3', Now},     %% Expired tokens
                {'=<', '$4', 0}        %% Exhausted tokens
              },
              {'=<', '$3', MaxAge}     %% Older than MaxAge
              ],
              ['$1']}],
            read
        ),

        %% Delete each token
        lists:foreach(
            fun(Token) ->
                mnesia:delete({invite_token, Token})
            end,
            Tokens
        ),
        length(Tokens)
    end,

    case mnesia:transaction(F) of
        {atomic, Count} ->
            ?INFO_MSG("mod_register_invite: Cleaned up ~p expired or exhausted tokens", [Count]),
            {ok, Count};
        {aborted, Reason} ->
            ?ERROR_MSG("mod_register_invite: Failed to clean up expired tokens: ~p", [Reason]),
            {error, Reason}
    end.


%%%===================================================================
%%% Registration Hook
%%%===================================================================
check_token(_User, _Host, Packet) ->
    Token = extract_token(Packet),
    case validate_and_decrement(Token) of
        ok     -> ok;
        Reason -> {error, Reason}
    end.

extract_token(Packet) ->
    case fxml:get_path_s(Packet, ["iq","query","token"]) of
        <<>> -> extract_token_from_password(Packet);
        T    -> T
    end.

extract_token_from_password(Packet) ->
    Pass   = fxml:get_path_s(Packet, ["iq","query","password"]),
    Prefix = <<"token:">>,
    case binary:match(Pass, Prefix) of
        {0,_} -> binary:part(Pass, byte_size(Prefix), byte_size(Pass)-byte_size(Prefix));
        nomatch -> <<>>
    end.

peek_token(Token) ->
    Fun = fun() ->
        case mnesia:read(invite_token, Token, read) of
          [#invite_token{expiry=Exp, uses_left=Uses}] ->
              Now = erlang:system_time(second),
              if
                Exp =< Now     -> expired;
                Uses =< 0      -> exhausted;
                true           -> ok
              end;
          [] ->
              invalid
        end
    end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

validate_and_decrement(Token) ->
    Fun = fun() ->
        case mnesia:read(invite_token, Token, write) of
            [#invite_token{expiry = Exp, uses_left = Uses} = Rec] ->
                Now = erlang:system_time(second),
                ?INFO_MSG("mod_register_invite: Validating token=~s now=~p expiry=~p uses_left=~p", [Token, Now, Exp, Uses]),
                if Exp > Now ->
                       case Uses of
                           0 -> exhausted;
                           _ -> mnesia:write(Rec#invite_token{uses_left = Uses - 1}),
                                ?INFO_MSG("mod_register_invite: Token=~s used, new uses_left=~p",[Token,Uses-1]),
                                ok
                       end;
                   true -> expired
                end;
            [] -> ?WARNING_MSG("mod_register_invite: Token=~s not found in Mnesia", [Token]),
                  invalid

        end
    end,
    {atomic, Res} = mnesia:transaction(Fun),
    ?INFO_MSG("mod_register_invite: Validation result for token=~s -> ~p", [Token, Res]),
    Res.


%%iq_commands() ->
%%    [{<<"vCard">>, <<"vcard-temp">>, handle_iq}].

handle_iq(#iq{type = get, to = #jid{luser= <<"invite">>}} = IQ, _From) ->
  ?INFO_MSG("mod_register_invite: Handing vCard request: ~p", [IQ]),

  To = xmpp:get_to(IQ),
  Host = To#jid.server,
  Token = new_token(Host,
    get_opt(Host, token_lifetime),
    get_opt(Host, default_uses)),
  Url   = format_token(url, Host, Token),
  ?INFO_MSG("mod_register_invite: Generated token for vCard: ~s",[Token]),

  VCard = #vcard_temp{
    fn = <<"Invitation Service">>,
    nickname = <<"Invite Bot">>,
    desc = <<"Use this service to request registration tokens">>,
    url = <<Url>>
  },
  xmpp:make_iq_result(IQ, VCard);

handle_iq(IQ, _From) ->
    ?INFO_MSG("mod_register_invite: Rejecting unhandled IQ: ~p", [IQ]),
    xmpp:make_error(IQ, xmpp:err_service_unavailable()).


%%%===================================================================
%%% Ad-hoc discovery
%%%===================================================================
adhoc_local_items({result, Items}, _From, #jid{lserver = Host}, _Lang) ->
    CmdItem = #disco_item{
        jid  = jid:make(Host),
        node = <<"generate_invite">>,
        name = <<"Generate Invite">>
    },
    {result, [CmdItem | Items]};
adhoc_local_items(Acc, _, _, _) ->
    Acc.

%%%===================================================================
%%% Ad-hoc command: generate & return URL
%%%===================================================================
adhoc_local_commands(
    _Acc,
    _From,
    #jid{lserver = Host},
    Request = #adhoc_command{node = <<"generate_invite">>, action = execute}
) ->
    Uses  = proplists:get_value(default_uses, mod_options(Host)),
    Life  = proplists:get_value(token_lifetime, mod_options(Host)),
    ?INFO_MSG("mod_register_invite: Generating invite for host=~p users=~p lifetime=~p", [Host, Uses, Life]),
    Url   = generate_invite_url(Host, Uses, Life),
    %% update & return command record
    Request#adhoc_command{
      status = completed,
      notes  = [#adhoc_note{type = info, data = Url}]
    };

adhoc_local_commands(Acc, _, _, _) ->
    Acc.

%%%===================================================================
%%% Invite URL generator
%%%===================================================================
-spec generate_invite_url(binary(), non_neg_integer(), non_neg_integer()) -> binary().
generate_invite_url(Host, Uses, LifetimeSecs) ->
    Token = new_token(Host, LifetimeSecs, Uses),
    format_token(url, Host, Token).

%%%===================================================================
%%% Helpers
%%%===================================================================
new_token(Host, Lifetime, Uses) ->
    Bin      = crypto:strong_rand_bytes(16),
    TokenBin = base64:encode(Bin),
    [RawTok | _] = binary:split(TokenBin, <<"=">>, [global]),
    Tok1     = binary:replace(RawTok, <<"+">>, <<"-">>, [global]),
    Tok      = binary:replace(Tok1, <<"/">>, <<"_">>, [global]),
    Exp      = erlang:system_time(second) + Lifetime,
    Rec      = #invite_token{token = Tok, host = Host, expiry = Exp, uses_left = Uses},
    {atomic, WriteResult} = 
      mnesia:transaction(fun() -> mnesia:write(Rec) end),
    ?INFO_MSG("mod_register_invite: Mnesia write for token~s -> ~p", [Tok, WriteResult]),
    ?INFO_MSG("mod_register_invite: New invite token=~s expires=~p uses_left=~p", [Tok, Exp, Uses]),
    Tok.

format_token(url, Host, Token) ->
    Base = proplists:get_value(invite_base_url, mod_options(Host)),
    iolist_to_binary([Base, "?token=", Token]);
format_token(raw, _Host, Token) -> Token;
format_token(qr, Host, Token) ->
    BaseUrl = proplists:get_value(invite_base_url, mod_options(Host)),
    Url = <<BaseUrl/binary, "?token=", Token/binary>>,
    QRCode = qrcode:encode(Url),
    PngData = qrcode:png(QRCode,[{size, 250}]),
    <<"data:image/png;base64,", (base64:encode(PngData))/binary>>.

get_opt(Host, Key) ->
    case gen_mod:get_module_opts(Host, ?MODULE) of
        {ok, Opts} when is_list(Opts) -> proplists:get_value(Key, Opts);
        {ok, Map} when is_map(Map)   -> maps:get(Key, Map);
        Map when is_map(Map)         -> maps:get(Key, Map);
        empty                        -> proplists:get_value(Key, mod_options(Host))
    end.

%%--------------------------------------------------------------------
%% Handle incoming vCard‐GET for invite@… and reply with our URL vCard
%%--------------------------------------------------------------------

on_vcard_get(
    { #iq{
         type = get,
         id   = Id,
         from = FromJID,
         to   = #jid{user     = <<"invite">>,
                     server   = Host,
                     resource = _Resource}
      } = IQ,
      _RawXML
    },
    State
) ->
    ?INFO_MSG("mod_register_invite: on_vcard_get fired – host=~p from=~p id=~p",
              [Host, FromJID, Id]),

    %% Generate token + URL
    Token = new_token(Host,
                      get_opt(Host, token_lifetime),
                      get_opt(Host, default_uses)),
    Url   = format_token(url, Host, Token),

    %% Build and send vCard reply
    VCardElem = #xmlel{
                  name     = <<"vCard">>,
                  attrs    = [{<<"xmlns">>, <<"vcard-temp">>}],
                  children = [
                    #xmlel{
                      name     = <<"FN">>,
                      children = [{xmlcdata, <<"Invite Link">>}]
                    },
                    #xmlel{
                      name     = <<"URL">>,
                      children = [{xmlcdata, Url}]
                    }
                  ]
                },
    Reply = IQ#iq{
              type    = result,
              sub_els = [VCardElem]
            },
    ejabberd_router:route(Reply),
    {stop, State};

on_vcard_get(_Other, State) ->
    {pass, State}.


%%--------------------------------------------------------------------
%% On any chat message to invite@… send back a fresh invite link
%%--------------------------------------------------------------------

on_invite_message(Packet) ->
  try
    case Packet of
      {{message, _ID, _Type, _Lang, From, To, Body, _Els, _Sid, Children, _Meta}, _Extra}
        when is_tuple(From), is_tuple(To) ->
        case is_packet_to_ignore(Body, Children) of
          true ->
            Packet;
          false ->
            case {To#jid.luser, To#jid.lserver} of
              {<<"invite">>, Server} ->
                ?INFO_MSG("mod_register_invite: Processing chat message to invite@~s from ~s@~s",
                  [Server, From#jid.luser, From#jid.lserver]),
                ?INFO_MSG("mod_register_invite: Packet ~p",[Packet]),
                handle_invite_request(From, Server),
                Packet;
              _ ->
                Packet
            end
        end;
      _ ->
        ?DEBUG("mod_register_invite: Ignoring unrecognized packet structure: ~p", [Packet])
    end
  catch
    Error:Reason:Stack ->
      ?ERROR_MSG("mod_register_invite: Error processing packet in mod_register_invite: ~p:~p~n~p~nPacket: ~p",
        [Error, Reason, Stack, Packet])
  end,
  Packet.


is_body_empty_or_whitespace(Children) ->
  BodyElements = [El || El <- Children, fxml:get_tag_name(El) =:= <<"text">>],
  case BodyElements of
    [] ->
      true; % No body elements
    [BodyEl|_] ->
      BodyText = fxml:get_cdata(BodyEl),
      ?INFO_MSG("mod_register_invite: Body text: ~p",[BodyText]),
      %% Check if it's empty or whitespace-only
      byte_size(string:trim(BodyText)) =:= 0
  end.

%% Helper function to check / filter chat state notifications
is_packet_to_ignore(undefined, _Children) ->
  %% No body element, we should return true.
  true;
is_packet_to_ignore(Body, Children) ->
    IsEmptyBody = is_body_empty_or_whitespace(Children),

    HasChatState =
        lists:any(fun
                      (#xmlel{name = Name}) ->
                          lists:member(Name,
                                        [<<"active">>, <<"composing">>,
                                         <<"paused">>, <<"inactive">>,
                                         <<"gone">>]);
                      (_) ->
                          false
                  end,
                  Children),

    IsChatState = IsEmptyBody orelse HasChatState,
    ?INFO_MSG(
        "mod_register_invite: Is chat state: ~p; Empty: ~p, ChatState: ~p",
        [IsChatState, IsEmptyBody, HasChatState]),
    IsChatState.

%% Helper function to handle actual message processing
handle_invite_request(From, Server) ->
    ?INFO_MSG("mod_register_invite: Processing invitation request from ~s@~s",
             [From#jid.luser, From#jid.lserver]),

    % Generate a registration token
    Token = new_token(Server,
        get_opt(Server, token_lifetime),
        get_opt(Server, default_uses)),
    Url = format_token(url, Server, Token),

    % Create a proper JID for the response
    FromJID = jid:make(<<"invite">>, Server, <<>>),

    % Create the response message with properly formatted body
    BodyText = <<"Your invitation link for registration: ", Url/binary, "\nPlease share securely with the person you wish to invite.">>,

    % Create a message with properly structured body element
    Message = #message{
        id = p1_rand:get_string(),
        type = chat,
        from = FromJID,
        to = From,
        body = xmpp:mk_text(BodyText),
        lang = <<"en">>
    },

    % Send the message
    ejabberd_router:route(Message).
