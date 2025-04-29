%%%----------------------------------------------------------------------
%%% @doc  Invite-only web registration for ejabberd.
%%%----------------------------------------------------------------------
-module(mod_register_invite_web).
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

%% HTTP handler callbacks ----------------------------------------------
-export([
    form_new_get/3,
    form_new_post/2,
    form_changepass_get/2,
    form_changepass_post/1,
    form_del_get/2,
    form_del_post/1
]).

-include_lib("ejabberd/include/ejabberd.hrl").
-include_lib("xmpp/include/xmpp.hrl").

-record(xmlcdata, {content :: binary()}).

%%%===================================================================
%%% Lifecycle
%%%===================================================================
start(_Host, _Opts) ->
    ok.

stop(_Host) ->
    ok.

depends(_Host, _Opts) ->
    [{mod_register_web, hard}, {mod_register_invite, hard}].

mod_options(_) -> [];
mod_opt_type(_) -> [];
mod_doc() ->
    #{desc => [
        "Provides an invite-only web interface for account registration.",
        "Reuses mod_register_web form and requires a valid invite token generated via XMPP."
    ]}.

%%%===================================================================
%%% Registration Form GET
%%%===================================================================
%% Delegates to mod_register_web to build full form, then injects hidden token field
form_new_get(Host, Lang, CaptchaEls) ->
    %% Get original form output
    {Status, Headers, Body} = mod_register_web:form_new_get(Host, Lang, CaptchaEls),
    %% Hidden token input to insert before closing </form>
    Hidden = <<"<input type=\"hidden\" name=\"token\" id=\"token\" value=\"\"/>">>,
    %% Replace closing form tag with token + closing tag
    NewBody = binary:replace(Body, <<"</form>">>, <<Hidden/binary, "</form>">>, [global]),
    {Status, Headers, NewBody}.

%%%===================================================================
%%% Registration Form POST
%%%===================================================================
form_new_post(Q, Ip) ->
    case get_register_parameters(Q) of
        {ok, Username, Host, Password, Password, Token} ->
            case mod_register_invite:validate_and_decrement(Token) of
                ok -> mod_register_web:register_account(Username, Host, Password, Ip);
                expired   -> {error, token_expired};
                exhausted -> {error, token_used};
                invalid   -> {error, token_invalid}
            end;
        _ -> {error, wrong_parameters}
    end.

%%%===================================================================
%%% Change Password & Unregister
%%%===================================================================
form_changepass_get(Host, Lang) ->
    mod_register_web:form_changepass_get(Host, Lang).

form_changepass_post(Q) ->
    mod_register_web:form_changepass_post(Q).

form_del_get(Host, Lang) ->
    mod_register_web:form_del_get(Host, Lang).

form_del_post(Q) ->
    mod_register_web:form_del_post(Q).

%%%----------------------------------------------------------------------
%%% Helper: extract parameters including token
%%%----------------------------------------------------------------------
get_register_parameters(Q) ->
    %% Expect list of tuples Name=Value
    case [Value || {<<"username">>, Value} <- Q] of
        [Username] ->
            [Host] = [V || {<<"host">>, V} <- Q],
            [Password] = [V || {<<"password">>, V} <- Q],
            [Password2] = [V || {<<"password2">>, V} <- Q],
            [Token] = [V || {<<"token">>, V} <- Q],
            if Password == Password2 ->
                    {ok, Username, Host, Password, Password2, Token};
               true -> {error, mismatched_passwords}
            end;
        _ ->
            {error, wrong_parameters}
    end.

