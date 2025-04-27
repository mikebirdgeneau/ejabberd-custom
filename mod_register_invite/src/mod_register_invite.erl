%%%----------------------------------------------------------------------
%%% @doc  Invite‑only in‑band registration for ejabberd.
%%%----------------------------------------------------------------------
-module(mod_register_invite).
-behaviour(gen_mod).

%% API callbacks -------------------------------------------------------
-export([start/2, 
         stop/1, 
         depends/2,
         mod_options/1, 
         mod_opt_type/1, 
         mod_doc/0]).

%% Hook callbacks ------------------------------------------------------
-export([check_token/3, 
         adhoc_local_items/4,
         adhoc_local_commands/4]).

-include_lib("xmpp/include/xmpp.hrl").
-record(xmlcdata, {content :: binary()}).

-record(invite_token, {
          token      :: binary(),
          host       :: binary(),
          expiry     :: integer(),   %% epoch seconds
          uses_left  :: integer()
         }).

%%%===================================================================
%%% Lifecycle
%%%===================================================================
start(Host, _Opts) ->
    ensure_table(),
    ejabberd_hooks:add(pre_registration,     Host, ?MODULE, check_token,          80),
    ejabberd_hooks:add(adhoc_local_items, Host, ?MODULE, adhoc_local_items, 50),
    ejabberd_hooks:add(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 50),
    ok.

stop(Host) ->
    ejabberd_hooks:delete(pre_registration,     Host, ?MODULE, check_token,          80),
    ejabberd_hooks:delete(adhoc_local_items, Host, ?MODULE, adhoc_local_items, 50),
    ejabberd_hooks:delete(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 50),
    ok.

depends(_Host, _Opts) -> [{mod_adhoc, hard}].

mod_doc() -> "Invite‑only registration with expiring tokens".

%%%-------------------------------------------------------------------
%%% Options
%%%-------------------------------------------------------------------
mod_options(Host) ->
    DefaultBase = <<"https://", Host/binary, "/register">>,
    [{token_lifetime, 86400},      %% seconds
     {default_uses,   1},
     {invite_base_url, DefaultBase}].

%% Validator (pattern used in ejabberd-contrib)
mod_opt_type(token_lifetime)  -> econf:pos_int();
mod_opt_type(default_uses)    -> econf:pos_int();
mod_opt_type(invite_base_url) -> econf:string();
mod_opt_type(_)               -> [token_lifetime, default_uses, invite_base_url].

%%%===================================================================
%%% Registration Hook
%%%===================================================================
check_token(_User, _Host, Packet) ->
    Token = extract_token(Packet),
    case validate_and_decrement(Token) of
        ok     -> ok;                    % allow
        Reason -> {error, Reason}
    end.

extract_token(Packet) ->
    case xml:get_path_s(Packet, ["iq","query","token"]) of
        <<>>  -> extract_token_from_password(Packet);
        Token -> Token
    end.

extract_token_from_password(Packet) ->
    Pass   = xml:get_path_s(Packet, ["iq","query","password"]),
    Prefix = <<"token:">>,
    case binary:match(Pass, Prefix) of
        {0, _} -> binary:part(Pass, byte_size(Prefix), byte_size(Pass) - byte_size(Prefix));
        nomatch -> <<>>
    end.

validate_and_decrement(Token) ->
    Fun = fun() ->
        case mnesia:read(invite_token, Token, write) of
            [#invite_token{expiry = Exp, uses_left = Uses} = Rec] ->
                Now = erlang:system_time(second),
                if Exp > Now ->
                       case Uses of
                           0 -> exhausted;
                           _ -> mnesia:write(Rec#invite_token{uses_left = Uses - 1}), ok
                       end;
                   true -> expired
                end;
            [] -> invalid
        end
    end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

%%%===================================================================
%%% Ad‑hoc command exposure
%%%===================================================================
%% When Service Discovery lists commands, ejabberd calls this hook.

adhoc_local_items({result, Items}, _From, #jid{lserver = Host}, _Lang) ->
    CmdItem = #disco_item{
        jid  = jid:make(Host),
        node = <<"generate_invite">>,
        name = <<"Generate Invite">>
    },
    {result, [CmdItem | Items]};
adhoc_local_items(Acc, _, _, _) ->
    Acc.

adhoc_local_commands(_Acc, From, #jid{lserver = Host}, 
                    #adhoc_command{node = <<"generate_invite">>,
                                  lang = Lang, 
                                  sid = Sid}) ->
    %% generate_invite_command/4 returns {result, XmlelChildren}
    {value, generate_invite_command(From, Host, Lang, Sid)};
adhoc_local_commands(Acc, _From, _To, _Req) ->
    Acc.


%% Real handler for the command — signature required by ejabberd
generate_invite_command(_From, Host, _Lang, _Sid) ->
    Lifetime = get_opt(Host, token_lifetime),
    Uses     = get_opt(Host, default_uses),
    Token    = new_token(Host, Lifetime, Uses),
    Url      = format_token(url, Host, Token),
    {result, [#xmlel{name = <<"note">>,
                     attrs = [{<<"type">>, <<"info">>}],
                     children = [#xmlcdata{content = Url}]}]}.

%%%===================================================================
%%% Helpers
%%%===================================================================
new_token(Host, Lifetime, Uses) ->
    Token = base32:encode(crypto:strong_rand_bytes(16)),
    Exp   = erlang:system_time(second) + Lifetime,
    Rec   = #invite_token{token = Token, host = Host, expiry = Exp, uses_left = Uses},
    mnesia:transaction(fun() -> mnesia:write(Rec) end),
    Token.

format_token(url, Host, Token) ->
    Base = get_opt(Host, invite_base_url),
    list_to_binary(Base ++ "?host=" ++ binary_to_list(Host) ++ "&token=" ++ Token);
format_token(raw, _Host, Token) -> Token;
format_token(qr, Host, Token) ->
    Png = qrcode:encode(format_token(url, Host, Token)),
    <<"data:image/png;base64,", (base64:encode(Png))/binary>>.

get_opt(Host, Key) ->
    {ok, Opts} = gen_mod:get_module_opts(Host, ?MODULE),
    proplists:get_value(Key, Opts).

ensure_table() ->
    mnesia:create_table(invite_token,
        [{disc_copies, [node()]},
         {attributes, record_info(fields, invite_token)},
         {type, set}]),
    ok.

