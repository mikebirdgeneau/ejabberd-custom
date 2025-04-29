%%%---------------------------------------------------------------------
%%% @doc  Invite‑only in‑band registration for ejabberd with optional arguments
%%%---------------------------------------------------------------------
-module(mod_register_invite).
-behaviour(gen_mod).

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
    adhoc_local_commands/4
]).

-include_lib("xmpp/include/xmpp.hrl").  %% brings in adhoc_command, xdata, etc.
-include_lib("ejabberd/include/ejabberd.hrl").

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
    ejabberd_hooks:add(adhoc_local_items,    Host, ?MODULE, adhoc_local_items,    50),
    ejabberd_hooks:add(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 50),
    ok.

stop(Host) ->
    ejabberd_hooks:delete(pre_registration,     Host, ?MODULE, check_token,          80),
    ejabberd_hooks:delete(adhoc_local_items,    Host, ?MODULE, adhoc_local_items,    50),
    ejabberd_hooks:delete(adhoc_local_commands, Host, ?MODULE, adhoc_local_commands, 50),
    ok.

depends(_Host, _Opts) -> [{mod_adhoc, hard}].

%%%-------------------------------------------------------------------
mod_options(Host) ->
    DefaultBase = <<"https://", Host/binary, "/register">>,
    [{token_lifetime,   86400},    %% default seconds
     {default_uses,     1},
     {invite_base_url,  DefaultBase}
    ].

mod_opt_type(token_lifetime)   -> econf:pos_int();
mod_opt_type(default_uses)     -> econf:pos_int();
mod_opt_type(invite_base_url)  -> econf:string();
mod_opt_type(_)                -> [token_lifetime, default_uses, invite_base_url].

mod_doc() -> "Invite-only registration with expiring tokens (optional uses/lifetime)".

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
    case xml:get_path_s(Packet, ["iq","query","token"]) of
        <<>> -> extract_token_from_password(Packet);
        T    -> T
    end.

extract_token_from_password(Packet) ->
    Pass   = xml:get_path_s(Packet, ["iq","query","password"]),
    Prefix = <<"token:">>,
    case binary:match(Pass, Prefix) of
        {0,_} -> binary:part(Pass, byte_size(Prefix), byte_size(Pass)-byte_size(Prefix));
        nomatch -> <<>>
    end.

validate_and_decrement(Token) ->
    Fun = fun() ->
        case mnesia:read(invite_token, Token, write) of
            [#invite_token{expiry=Exp, uses_left=Uses} = Rec] ->
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
%%% Ad-hoc command: two-step form + generate URL
%%%===================================================================
%% Step 1: form request
adhoc_local_commands(
    Acc = #adhoc_command{node=<<"generate_invite">>, action=execute, form=undefined},
    _From,
    #jid{lserver = Host},
    _Req
) ->
    DefaultUses     = get_opt(Host, default_uses),
    DefaultLifetime = get_opt(Host, token_lifetime),
    Form = #xdata{
        xmlns        = <<"jabber:x:data">>,
        type         = form,
        title        = <<"Generate Invite">>,
        instructions = [<<"Set optional parameters or use defaults.">>],
        fields       = [
            #xdata_field{var=<<"uses">>,     type=<<"text-single">>, label=<<"Number of invites">>, required=false, value=integer_to_list(DefaultUses)},
            #xdata_field{var=<<"lifetime">>, type=<<"text-single">>, label=<<"Lifetime (sec)">>,       required=false, value=integer_to_list(DefaultLifetime)}
        ]
    },
    Acc#adhoc_command{status=executing, form=Form};

%% Step 2: form submitted -> generate URL
adhoc_local_commands(
    Acc = #adhoc_command{node=<<"generate_invite">>, action=execute, form=#xdata{fields=Fields}},
    _From,
    #jid{lserver = Host},
    _Req
) ->
    UsesStr     = proplists:get_value(<<"uses">>, Fields, integer_to_list(get_opt(Host, default_uses))),
    LifetimeStr = proplists:get_value(<<"lifetime">>, Fields, integer_to_list(get_opt(Host, token_lifetime))),
    {ok, Uses} = string:to_integer(UsesStr),
    {ok, Life} = string:to_integer(LifetimeStr),
    Url = generate_invite_url(Host, Uses, Life),
    Acc#adhoc_command{status=completed, notes=[#adhoc_note{type=info, data=Url}]};

%% Fallback
adhoc_local_commands(Acc, _From, _To, _Req) ->
    Acc.

%%%===================================================================
%%% Invite URL generator helper
%%%===================================================================
-spec generate_invite_url(binary(), non_neg_integer(), non_neg_integer()) -> binary().
generate_invite_url(Host, Uses, LifetimeSecs) ->
    Token = new_token(Host, LifetimeSecs, Uses),
    format_token(url, Host, Token).

%%%===================================================================
%%% Helpers
%%%===================================================================
new_token(Host, Lifetime, Uses) ->
    Bin = crypto:strong_rand_bytes(16),
    TokenBin = base64:encode(Bin),
    [Token | _] = binary:split(TokenBin, <<"=">>, [global]),
    TokenStr = binary_to_list(Token),
    Rec = #invite_token{token=TokenStr, host=Host,
                        expiry=erlang:system_time(second)+Lifetime,
                        uses_left=Uses},
    mnesia:transaction(fun() -> mnesia:write(Rec) end),
    TokenStr.

format_token(url, Host, Token) ->
    Base = get_opt(Host, invite_base_url),
    iolist_to_binary([Base, "?token=", Token]);
format_token(raw, _Host, Token) -> Token;
format_token(qr, Host, Token) ->
    Png = qrcode:encode(format_token(url, Host, Token)),
    <<"data:image/png;base64,", (base64:encode(Png))/binary>>.

get_opt(Host, Key) ->
    case gen_mod:get_module_opts(Host, ?MODULE) of
        {ok, Opts} when is_list(Opts) -> proplists:get_value(Key, Opts);
        {ok, OptMap} when is_map(OptMap) -> maps:get(Key, OptMap);
        OptMap when is_map(OptMap)         -> maps:get(Key, OptMap);
        empty                              -> proplists:get_value(Key, mod_options(Host))
    end.

ensure_table() ->
    mnesia:create_table(invite_token,
        [ {disc_copies, [node()]},
          {attributes, record_info(fields, invite_token)},
          {type, set}
        ]),
    ok.

