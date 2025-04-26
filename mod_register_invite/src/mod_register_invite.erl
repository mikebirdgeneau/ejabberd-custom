%%%----------------------------------------------------------------------
%%% @doc  An ejabberd module that enables invite‑only in‑band registration.
%%%       Existing users issue the "invite" ad‑hoc command (or call an
%%%       ejabberdctl command) which returns an URL or QR code containing
%%%       a time‑limited registration token.  When a client tries to
%%%       register a new account it must supply that token in the
%%%       <username/> element password field (or as a <token/> element,
%%%       see README below).  The module checks the token and either
%%%       allows or rejects the registration.
%%%
%%%  Author :  Mike Birdgeneau <mike.birdgeneau@gmail.com>
%%%  License:  MIT
%%%----------------------------------------------------------------------
-module(mod_register_invite).
-behaviour(gen_mod).

%% API ------------------------------------------------------------------
-export([start/2, stop/1, depends/2, mod_options/2, mod_doc/0]).

%% hooks
-export([check_token/3]).

%% ad‑hoc & commands
-export([adhoc_invite/4, ejabberd_ctl_create/3]).

-include_lib("ejabberd/include/ejabberd.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

%-record defs -----------------------------------------------------------
-record(invite_token, {
          token        :: binary(),
          host         :: binary(),
          expiry       :: integer(),   %% erlang:system_time(sec)
          uses_left    :: integer()    %% >0 means token is usable
         }).

%%%======================================================================
%%% Module lifecycle
%%%======================================================================
start(Host, Opts) ->
    ok = ensure_table(),
    %% Hook that fires *before* user is actually created (see mod_register)
    ejabberd_hooks:add(pre_registration, Host, ?MODULE, check_token, 80),

    %% Register an ad‑hoc command so any authenticated user can call it
    ejabberd_commands:register_command({create_invite, Host},
        {?MODULE, ejabberd_ctl_create},
        [token_type, validity, max_uses], string,
        "Create an invite token. token_type = url | qr | raw, "
        "validity = seconds from now (e.g. 86400), max_uses = integer"),

    %% Ad‑hoc (XEP‑0050) stanza command
    mod_adhoc:register(Host, ?MODULE, <<"Generate Invite">>, fun adhoc_invite/4),
    ok.

stop(Host) ->
    ejabberd_hooks:delete(pre_registration, Host, ?MODULE, check_token, 80),
    mod_adhoc:unregister(Host, ?MODULE),
    ejabberd_commands:unregister_command({create_invite, Host}),
    ok.

depends(_Host, _Opts) -> [].

mod_doc() ->
    "Invite‑only registration with expiring, single‑ or multi‑use tokens.".

mod_options(_Host) ->
    [{token_lifetime, 604800},     %% default 7 days
     {default_uses,   1},         %% default one‑time use
     {invite_base_url, "https://example.com/register"}].

%%%======================================================================
%%% Registration hook
%%%======================================================================
%% @spec check_token(User :: binary(), From :: binary(), Packet :: exml:element()) -> any()
%% The hook is executed by mod_register BEFORE actually creating the user.
%% We look for <token/> inside the IQ stanza or allow sending the token in
%% the password field (<password/> value = "token:TOKENSTRING") which is
%% useful for clients that do not understand extensions.
check_token(_User, _Host, Packet) ->
    Token = extract_token(Packet),
    case validate_and_decrement(Token) of
        ok -> ok;   %% allow registration to continue
        Error -> {error, Error}
    end.

extract_token(Packet) ->
    %% Quick & dirty XPath‑like extraction.  Adapt to your needs.
    case xml:get_path_s(Packet, ["iq", "query", "token"]) of
        <<>> -> %% fallback to password‑prefixed method
            case xml:get_path_s(Packet, ["iq", "query", "password"]) of
                Password when byte_size(Password) > 6,
                               binary:part(Password, 0, 6) =:= <<"token:">> ->
                     binary:part(Password, 6, byte_size(Password) - 6);
                _ -> <<>>
            end;
        Token -> Token
    end.

validate_and_decrement(<<>>) ->
    not_allowed;  %% no token at all
validate_and_decrement(Token) ->
    Fun = fun() ->
        case mnesia:read(invite_token, Token, write) of
            [#invite_token{expiry = Exp, uses_left = UsesLeft} = Rec] ->
                case Exp > erlang:system_time(second) of
                    false -> mnesia:delete(invite_token, Token, write), expired;
                    true  ->
                        case UsesLeft > 0 of
                            false -> mnesia:delete(invite_token, Token, write), exhausted;
                            true  ->
                                NewRec = Rec#invite_token{uses_left = UsesLeft - 1},
                                mnesia:write(NewRec, write),
                                ok
                        end
                end;
            [] -> invalid
        end
    end,
    {atomic, Result} = mnesia:transaction(Fun),
    Result.

%%%======================================================================
%%% Invite creation commands
%%%======================================================================
%% Called via ejabberdctl create_invite host url 86400 5
ejabberd_ctl_create(Host, [TypeStr, ValidityStr, UsesStr]) ->
    Type   = list_to_atom(TypeStr),
    ValidS = list_to_integer(ValidityStr),
    Uses   = list_to_integer(UsesStr),
    Token  = new_token(Host, ValidS, Uses),
    format_token(Type, Host, Token).

%% Ad‑hoc command implementation (authenticated user context)
adhoc_invite(_User, _Server, _Lang, _Session) ->
    Token = new_token(_Server, get(opt, token_lifetime), get(opt, default_uses)),
    Url   = format_token(url, _Server, Token),
    {result, [#xmlel{name = <<"note">>, attrs = [{<<"type">>, <<"info">>}],
               children = [#xmlcdata{content = Url}]}]}.

%%%----------------------------------------------------------------------
new_token(Host, Lifetime, Uses) ->
    Token = base32:encode(crypto:strong_rand_bytes(16)),
    Expiry = erlang:system_time(second) + Lifetime,
    Obj = #invite_token{token = Token, host = Host, expiry = Expiry, uses_left = Uses},
    mnesia:transaction(fun() -> mnesia:write(Obj) end),
    Token.

format_token(raw, _Host, Token) -> Token;
format_token(url, Host, Token) ->
    Base = get(opt, invite_base_url),
    Base ++ "?host=" ++ binary_to_list(Host) ++ "&token=" ++ Token;
format_token(qr, Host, Token) ->
    Url = format_token(url, Host, Token),
    %% Requires hexpm qrcode lib: qrcode:encode/1 returns PNG binary
    QR  = qrcode:encode(list_to_binary(Url)),
    DataURI = "data:image/png;base64," ++ base64:encode(QR),
    DataURI.

%%%======================================================================
%%% Helpers
%%%======================================================================
ensure_table() ->
    Tab = invite_token,
    mnesia:create_table(Tab, [{disc_copies, [node()]},
                              {attributes, record_info(fields, invite_token)}]),
    ok.

get(opt, Key) ->
    {ok, Opts} = gen_mod:get_module_opts(?MODULE),
    proplists:get_value(Key, Opts).
