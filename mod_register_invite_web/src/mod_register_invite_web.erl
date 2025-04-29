%%%----------------------------------------------------------------------
%%% @doc  Invite-only web registration for ejabberd.
%%%----------------------------------------------------------------------
-module(mod_register_invite_web).
-author('mike.birdgeneau@gmail.com').

-behaviour(gen_mod).

%% gen_mod callbacks
-export([start/2, stop/1, depends/2, mod_options/1, mod_opt_type/1]).

%% Web handlers
-export([process/2]).

-include_lib("xmpp/include/xmpp.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("ejabberd/include/ejabberd_http.hrl").
-include_lib("ejabberd/include/ejabberd_web_admin.hrl").

-record(xmlcdata, {content :: binary()}).

%%%===================================================================
%%% Lifecycle
%%%===================================================================
start(Host, _Opts) ->
    ?INFO_MSG("Starting mod_register_invite_web", []),
    ok.

stop(Host) ->
    ok.

depends(_Host, _Opts) ->
    [{mod_register_invite, hard}].

mod_options(_Host) ->
    [].

mod_opt_type(_) ->
    [].

process([], #request{method = 'GET', host = Host, lang = Lang, q = Q}) ->
    Token = proplists:get_value(<<"token">>, Q, <<"">>),
    CaptchaEls = build_captcha_els(Host, Lang),
    form_get(Host, Lang, CaptchaEls, Token);

process([], #request{method = 'POST', q = Q, ip = IP}) ->
    form_post(Q, IP);

process(_Path, _Request) ->
    {404, [], "Not Found"}.

form_get(Host, Lang, CaptchaEls, Token) ->
    HeadEls = [
        ?XCT("title", "Register an XMPP account"),
        ?XA("style", "type", "text/css", css())
    ],
    
    TokenField = case Token of
        <<"">> -> [?XCT("p", "Registration requires an invitation token.")];
        _ -> []
    end,
    
    FormEls = [
        ?XAE("form", [{"action", ""}, {"method", "post"}],
            TokenField ++
            [
                ?XE("fieldset", [
                    ?XCT("legend", "Register an XMPP account"),
                    ?XAE("p", [], [
                        ?XCT("label", "Username:"),
                        ?XA("input", [{"type", "text"}, {"name", "username"}, {"required", "required"}])
                    ]),
                    ?XAE("p", [], [
                        ?XCT("label", "Server:"),
                        ?XAC("input", [{"type", "text"}, {"name", "host"}, {"value", Host}, {"readonly", "readonly"}])
                    ]),
                    ?XAE("p", [], [
                        ?XCT("label", "Password:"),
                        ?XA("input", [{"type", "password"}, {"name", "password"}, {"required", "required"}])
                    ]),
                    ?XAE("p", [], [
                        ?XCT("label", "Confirm:"),
                        ?XA("input", [{"type", "password"}, {"name", "password2"}, {"required", "required"}])
                    ]),
                    ?XAE("p", [], [
                        ?XA("input", [{"type", "hidden"}, {"name", "token"}, {"value", Token}])
                    ]),
                    CaptchaEls,
                    ?XAE("p", [], [
                        ?XA("input", [{"type", "submit"}, {"name", "register"}, {"value", "Register"}])
                    ])
                ])
            ]
        )
    ],
    
    {200, [{"Content-Type", "text/html; charset=utf-8"}], 
     ejabberd_web:make_xhtml(HeadEls, FormEls)}.

form_post(Q, IP) ->
    case extract_form_data(Q) of
        {ok, Username, Host, Password, Password, Token} ->
            case mod_register_invite:validate_token(Token) of
                ok -> 
                    case ejabberd_auth:try_register(Username, Host, Password) of
                        {atomic, ok} ->
                            mod_register_invite:decrement_token(Token),
                            success_page();
                        Error ->
                            error_page("Registration failed", io_lib:format("Error: ~p", [Error]));
                    end;
                {error, Reason} ->
                    error_page("Invalid token", atom_to_list(Reason))
            end;
        {error, passwords_not_identical} ->
            error_page("Passwords don't match", "The passwords you entered don't match");
        {error, missing_parameter} ->
            error_page("Missing parameter", "All fields are required")
    end.

extract_form_data(Q) ->
    Username = proplists:get_value(<<"username">>, Q, <<"">>),
    Host = proplists:get_value(<<"host">>, Q, <<"">>),
    Password = proplists:get_value(<<"password">>, Q, <<"">>),
    Password2 = proplists:get_value(<<"password2">>, Q, <<"">>),
    Token = proplists:get_value(<<"token">>, Q, <<"">>),
    
    case {Username, Host, Password, Password2, Token} of
        {<<"">>, _, _, _, _} -> {error, missing_parameter};
        {_, <<"">>, _, _, _} -> {error, missing_parameter};
        {_, _, <<"">>, _, _} -> {error, missing_parameter};
        {_, _, _, <<"">>, _} -> {error, missing_parameter};
        {_, _, _, _, <<"">>} -> {error, missing_parameter};
        {_, _, Password, Password2, _} when Password =/= Password2 ->
            {error, passwords_not_identical};
        {U, H, P, P, T} ->
            {ok, U, H, P, P, T}
    end.

success_page() ->
    {200, [{"Content-Type", "text/html; charset=utf-8"}],
     ejabberd_web:make_xhtml(
       [?XCT("title", "Registration successful")],
       [?XE("h1", [?CT("Registration successful")]),
        ?XE("p", [?CT("Your XMPP account has been registered.")])
       ])}.

error_page(Title, Message) ->
    {200, [{"Content-Type", "text/html; charset=utf-8"}],
     ejabberd_web:make_xhtml(
       [?XCT("title", Title)],
       [?XE("h1", [?CT(Title)]),
        ?XE("p", [?CT(Message)])
       ])}.

build_captcha_els(Host, Lang) ->
    case ejabberd_captcha:is_feature_available() of
        true -> ejabberd_captcha:build_captcha_html(Host, Lang);
        false -> []
    end.

css() ->
    "
    body {
        font-family: Arial, sans-serif;
        max-width: 500px;
        margin: 0 auto;
        padding: 20px;
    }
    fieldset {
        border: 1px solid #ccc;
        padding: 20px;
        margin-bottom: 20px;
    }
    label {
        display: block;
        margin-bottom: 5px;
        font-weight: bold;
    }
    input[type='text'], input[type='password'] {
        width: 100%;
        padding: 8px;
        margin-bottom: 15px;
        box-sizing: border-box;
    }
    input[type='submit'] {
        background-color: #4CAF50;
        color: white;
        padding: 10px 15px;
        border: none;
        cursor: pointer;
    }
    .error {
        color: red;
        font-weight: bold;
    }
    ".

