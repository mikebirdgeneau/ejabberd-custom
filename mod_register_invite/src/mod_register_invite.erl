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

%%----------------------------------------------------------------------
%% API
%%----------------------------------------------------------------------
-export([
    start/2,
    stop/1,
    depends/2,
    mod_options/1,
    mod_opt_type/1,
    mod_doc/0
]).

%% Hooks
-export([check_token/3]).

%% Ad‑hoc command
-export([adhoc_invite/4]).

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
    ejabberd_hooks:add(pre_registration, Host, ?MODULE, check_token, 80),
    mod_adhoc:register(Host, ?MODULE, <<"Generate Invite">>, fun adhoc_invite/4),
    ok.

stop(Host) ->
    ejabberd_hooks:delete(pre_registration, Host, ?MODULE, check_token, 80),
    mod_adhoc:unregister(Host, ?MODULE),
    ok.

depends(_Host, _Opts) -> [].

mod_doc() -> "Invite‑only registration with expiring tokens".

%% default values (override in ejabberd.yml)
mod_options(_Host) ->
    [{token_lifetime, 86400},      %% 1 day
     {default_uses,   1},
     {invite_base_url, "https://example.com/register"}].

mod_opt_type(_Host) ->
    yconf:ok([
      {token_lifetime, integer},
      {default_uses,  integer},
      {invite_base_url, string}
    ]).

%%%===================================================================
%%% Registration Hook
%%%===================================================================
check_token(_User, _Host, Packet) ->
    Token = extract_token(Packet),
    case validate_and_decrement(Token) of
        ok     -> ok;                    % allow
        Reason -> {error, Reason}        % block
    end.

extract_token(Packet) ->
    %% 1) explicit <token> element
    case xml:get_path_s(Packet, ["iq","query","token"]) of
        <<>> -> extract_token_from_password(Packet);
        Token -> Token
    end.

extract_token_from_password(Packet) ->
    Pass = xml:get_path_s(Packet, ["iq","query","password"]),
    Prefix = <<"token:">>,
    case binary:match(Pass, Prefix) of
        {0,_Len} -> binary:part(Pass, byte_size(Prefix), byte_size(Pass)-byte_size(Prefix));
        nomatch  -> <<>>
    end.

validate_and_decrement(Token) ->
    Fun = fun() ->
        case mnesia:read(invite_token, Token, write) of
            [#invite_token{expiry = Exp, uses_left = Uses}=Rec] ->
                Now = erlang:system_time(second),
                if Exp > Now ->
                    case Uses of
                        0 -> exhausted;
                        _ -> mnesia:write(Rec#invite_token{uses_left=Uses-1}), ok
                    end;
                true -> expired
                end;
            [] -> invalid
        end
    end,
    {atomic, Res} = mnesia:transaction(Fun),
    Res.

%%%===================================================================
%%% Ad-hoc command (XEP‑0050)
%%%===================================================================
adhoc_invite(_User, Host, _Lang, _Session) ->
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
    Exp   = os:system_time(second)+Lifetime,
    Rec   = #invite_token{token=Token,host=Host,expiry=Exp,uses_left=Uses},
    mnesia:transaction(fun() -> mnesia:write(Rec) end),
    Token.

format_token(url, Host, Token) ->
    Base = get_opt(Host, invite_base_url),
    list_to_binary(Base ++ "?host=" ++ binary_to_list(Host) ++ "&token=" ++ Token);
format_token(raw, _H, T) -> T;
format_token(qr, Host, Token) ->   % optional dependency
    PngBin = qrcode:encode(format_token(url, Host, Token)),
    <<"data:image/png;base64,", (base64:encode(PngBin))/binary>>.

get_opt(Host, Key) ->
    {ok, Opts} = gen_mod:get_module_opts(Host, ?MODULE),
    proplists:get_value(Key, Opts).

ensure_table() ->
    mnesia:create_table(invite_token,
        [{disc_copies,[node()]},
         {attributes, record_info(fields, invite_token)},
         {type, set}]),
    ok.
