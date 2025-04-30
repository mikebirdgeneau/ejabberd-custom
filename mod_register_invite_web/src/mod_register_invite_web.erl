%%%-------------------------------------------------------------------
%%% @doc  Invite‑only in‑band registration via web (HTTP) for ejabberd
%%%-------------------------------------------------------------------
-module(mod_register_invite_web).
-behaviour(gen_mod).
-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("ejabberd/include/ejabberd_http.hrl").
-include_lib("ejabberd/include/ejabberd_web_admin.hrl").
-include_lib("ejabberd/include/translate.hrl").

-export([start/2, stop/1, reload/3, process/2, mod_options/1, depends/2, mod_doc/0]).

%%%===================================================================
%%% Lifecycle
%%%===================================================================

start(_Host, _Opts) ->
    ok.

stop(_Host) ->
    ok.

reload(_Host, _NewOpts, _OldOpts) ->
    ok.

depends(_Host, _Opts) ->
    [{mod_register_invite, hard},  %% require invite module
     {mod_register,      hard}].   %% require base register module

%%%===================================================================
%%% HTTP handler
%%%===================================================================
process(Path, Request) ->
    %% Delegate static path handling from mod_register_web
    case Path of
        [<<"register.css">>] when Request#request.method =:= 'GET' ->
            serve_css();
        _ ->
            process2(Path, Request)
    end.

process2([], #request{method = 'GET', lang = Lang}) ->
    index_page(Lang);

%% GET handlers
process2([Section], #request{method = 'GET', q = Q, lang = Lang, host = HTTPHost, ip = {IP,_P}}) ->
    Host = case ejabberd_router:is_my_host(HTTPHost) of true -> HTTPHost; false -> <<>> end,
    case Section of
        <<"new">> ->
            case lists:keyfind(<<"token">>, 1, Q) of
                {_, Token} -> handle_new_get(Token, Host, Lang, IP);
                false       -> missing_token()
            end;
        <<"delete">> -> form_del_get(Host, Lang);
        <<"change_password">> -> form_changepass_get(Host, Lang);
        _ -> {404, [], "Not Found"}
    end;

%% POST handlers
process2([<<"new">>], #request{method = 'POST', q = Q, lang = Lang, ip = {IP,_P}}) ->
    case lists:keyfind(<<"token">>, 1, Q) of
        {_, Token} -> handle_new_post(Token, Q, Lang, IP);
        false      -> missing_token()
    end;

process2([<<"delete">>], #request{method = 'POST', q = Q, lang = _Lang}) ->
    form_del_post(Q);
process2([<<"change_password">>], #request{method = 'POST', q = Q, lang = _Lang}) ->
    form_changepass_post(Q);
process2(_, _) ->
    {404, [], "Not Found"}.

%%%===================================================================
%%% Helpers for missing/invalid token
%%%===================================================================
missing_token() ->
    Body = "<h2>Missing invitation token</h2>",
    {403, [], Body}.

invalid_token() ->
    Body = "<h2>Invalid or expired token</h2>",
    {403, [], Body}.

%%%===================================================================
%%% Invitation-protected registration GET
%%%===================================================================
handle_new_get(Token, Host, Lang, IP) ->
    ?INFO_MSG("HTTP GET /register/new?token=~p from ~p", [Token, IP]),
    case mod_register_invite:peek_token(Token) of
      ok -> form_new_get(Token, Host, Lang, IP);
      expired -> ?INFO_MSG("Token Expired (~p)", [Token]),
                 invalid_token(expired);
      exhausted -> ?INFO_MSG("Token Exhausted (~p)", [Token]),
                   invalid_token(exhausted);
      invalid -> ?INFO_MSG("Token Invalid (~p)", [Token]),
                 invalid_token(invalid)
    end.

%%%===================================================================
%%% Invitation-protected registration POST
%%%===================================================================
handle_new_post(Token, Q, Lang, IP) ->
    ?INFO_MSG("HTTP POST /register/new?token=~p form-data=~p from ~p", [Token, Q, IP]),
    case validate_token(Token) of
        ok -> form_new_post(Q, IP);
        _  -> invalid_token()
    end.

validate_token(Token) ->
    %% Assume mod_register_invite provides this call
    ?INFO_MSG("Web validating token=~s", [Token]),
    case catch mod_register_invite:validate_and_decrement(Token) of
        ok      -> ok;
        expired -> expired;
        invalid -> invalid;
        exhausted -> exhausted;
        Other -> ?ERROR_MSG("Unexpected result from validate_and_decrement: ~p",[Other]),
             invalid
    end.

%%%===================================================================
%%% Copied and adapted from mod_register_web
%%%===================================================================
serve_css() ->
    case css() of {ok, CSS} -> {200, [{<<"Content-Type">>, <<"text/css">>}], CSS}; error -> {404, [], "CSS not found"} end.

css() ->
    Dir = misc:css_dir(),
    File = filename:join(Dir, "register.css"),
    case file:read_file(File) of
        {ok, Data}      -> {ok, Data};
        {error, _Why}    -> error
    end.

index_page(Lang) ->
  HeadEls = [ 
             ?XAE(<<"meta">>,
                  [{<<"http-equiv">>, <<"Content-Type">>},
                   {<<"content">>,     <<"text/html; charset=utf-8">>}],
                  []),
             ?XCT(<<"title">>, ?T("XMPP Account Registration")),
             ?XA(<<"link">>, [{<<"href">>, <<"register.css">>}, {<<"rel">>, <<"stylesheet">>}])],
  Els = [?XACT(<<"h1">>, [{<<"class">>, <<"title">>}], ?T("XMPP Account Registration")),
         ?XE(<<"ul">>, [?XE(<<"li">>, [?ACT(<<"new/?token=TOKEN">>, ?T("Register via Invite"))])])],
  {200, [{<<"Content-Type">>, <<"text/html">>}], ejabberd_web:make_xhtml(HeadEls, Els)}.


%%%----------------------------------------------------------------------
%%% Formulary new account GET
%%%----------------------------------------------------------------------

form_new_get(Token, Host, Lang, IP) ->
    try build_captcha_li_list(Lang, IP) of
	CaptchaEls ->
	    form_new_get2(Token, Host, Lang, CaptchaEls)
	catch
	    throw:Result ->
		?DEBUG("Unexpected result when creating a captcha: ~p", [Result]),
		ejabberd_web:error(not_allowed)
    end.

form_new_get2(Token, Host, Lang, CaptchaEls) ->
  TokenInput = ?XAE(<<"input">>,
       [
         {<<"type">>,  <<"hidden">>},
         {<<"name">>,  <<"token">>},
         {<<"value">>, Token}
       ],
       []),
  HeadEls = [ 
             ?XAE(<<"meta">>,
                  [{<<"http-equiv">>, <<"Content-Type">>},
                   {<<"content">>,     <<"text/html; charset=utf-8">>}],
                  []),
             ?XCT(<<"title">>,
                  ?T("Register an XMPP account")),
             ?XA(<<"link">>,
                 [{<<"href">>, <<"../register.css">>},
                  {<<"type">>, <<"text/css">>},
                  {<<"rel">>, <<"stylesheet">>}])],
  Els = [?XACT(<<"h1">>,
               [{<<"class">>, <<"title">>},
                {<<"style">>, <<"text-align:center;">>}],
               ?T("Register an XMPP account")),
         ?XCT(<<"p">>,
              ?T("This page allows to register an XMPP "
                 "account in this XMPP server. Your "
                 "JID (Jabber ID) will be of the "
                 "form: username@server. Please read carefully "
                 "the instructions to fill correctly the "
                 "fields.")),
         ?XAE(<<"form">>,
              [{<<"action">>, <<"">>}, {<<"method">>, <<"post">>}],
              [TokenInput,
               ?XE(<<"ol">>,
                   ([?XE(<<"li">>,
                         [?CT(?T("Username:")), ?C(<<" ">>),
                          ?INPUTS(<<"text">>, <<"username">>, <<"">>,
                                  <<"20">>),
                          ?BR,
                          ?XE(<<"ul">>,
                              [?XCT(<<"li">>,
                                    ?T("This is case insensitive: macbeth is "
                                       "the same that MacBeth and Macbeth.")),
                               ?XC(<<"li">>,
                                   <<(translate:translate(Lang, ?T("Characters not allowed:")))/binary,
                                     " \" & ' / : < > @ ">>)])]),
                     ?XE(<<"li">>,
                         [?CT(?T("Server:")), ?C(<<" ">>),
                          ?INPUTS(<<"text">>, <<"host">>, Host, <<"20">>)]),
                     ?XE(<<"li">>,
                         [?CT(?T("Password:")), ?C(<<" ">>),
                          ?INPUTS(<<"password">>, <<"password">>, <<"">>,
                                  <<"20">>),
                          ?BR,
                          ?XE(<<"ul">>,
                              [?XCT(<<"li">>,
                                    ?T("Don't tell your password to anybody, "
                                       "not even the administrators of the XMPP "
                                       "server.")),
                               ?XCT(<<"li">>,
                                    ?T("You can later change your password using "
                                       "an XMPP client.")),
                               ?XCT(<<"li">>,
                                    ?T("Some XMPP clients can store your password "
                                       "in the computer, but you should do this only "
                                       "in your personal computer for safety reasons.")),
                               ?XCT(<<"li">>,
                                    ?T("Memorize your password, or write it "
                                       "in a paper placed in a safe place. In "
                                       "XMPP there isn't an automated way "
                                       "to recover your password if you forget "
                                       "it."))])]),
                     ?XE(<<"li">>,
                         [?CT(?T("Password Verification:")), ?C(<<" ">>),
                          ?INPUTS(<<"password">>, <<"password2">>, <<"">>,
                                  <<"20">>)])]
                    ++
                    CaptchaEls ++
                    [?XE(<<"li">>,
                         [?INPUTT(<<"submit">>, <<"register">>,
                                  ?T("Register"))])]))])],
  {200,
   [{<<"Server">>, <<"ejabberd">>},
    {<<"Content-Type">>, <<"text/html">>}],
   ejabberd_web:make_xhtml(HeadEls, Els)}.

%% Copied from mod_register.erl
%% Function copied from ejabberd_logger_h.erl and customized
%%%----------------------------------------------------------------------
%%% Formulary new POST
%%%----------------------------------------------------------------------

form_new_post(Q, Ip) ->
    case catch get_register_parameters(Q) of
      [Username, Host, Password, Password, Id, Key] ->
	  form_new_post(Username, Host, Password, {Id, Key}, Ip);
      [_Username, _Host, _Password, _Password2, false, false] ->
	  {error, passwords_not_identical};
      [_Username, _Host, _Password, _Password2, Id, Key] ->
	  ejabberd_captcha:check_captcha(Id, Key),
	  {error, passwords_not_identical};
      _ -> {error, wrong_parameters}
    end.

get_register_parameters(Q) ->
    lists:map(fun (Key) ->
		      case lists:keysearch(Key, 1, Q) of
			{value, {_Key, Value}} -> Value;
			false -> false
		      end
	      end,
	      [<<"username">>, <<"host">>, <<"password">>, <<"password2">>,
	       <<"id">>, <<"key">>]).

form_new_post(Username, Host, Password, {false, false}, Ip) ->
    register_account(Username, Host, Password, Ip);
form_new_post(Username, Host, Password, {Id, Key}, Ip) ->
    case ejabberd_captcha:check_captcha(Id, Key) of
      captcha_valid ->
	  register_account(Username, Host, Password, Ip);
      captcha_non_valid -> {error, captcha_non_valid};
      captcha_not_found -> {error, captcha_non_valid}
    end.

%%%----------------------------------------------------------------------
%%% Formulary Captcha support for new GET/POST
%%%----------------------------------------------------------------------

build_captcha_li_list(Lang, IP) ->
    case ejabberd_captcha:is_feature_available() of
      true -> build_captcha_li_list2(Lang, IP);
      false -> []
    end.

build_captcha_li_list2(Lang, IP) ->
    SID = <<"">>,
    From = #jid{user = <<"">>, server = <<"test">>,
		resource = <<"">>},
    To = #jid{user = <<"">>, server = <<"test">>,
	      resource = <<"">>},
    Args = [],
    case ejabberd_captcha:create_captcha(
	   SID, From, To, Lang, IP, Args) of
	{ok, Id, _, _} ->
	    case ejabberd_captcha:build_captcha_html(Id, Lang) of
		{_, {CImg, CText, CId, CKey}} ->
		    [?XE(<<"li">>,
			 [CText, ?C(<<" ">>), CId, CKey, ?BR, CImg])];
		Error ->
		    throw(Error)
	    end;
	Error ->
	    throw(Error)
    end.

%%%----------------------------------------------------------------------
%%% Formulary change password GET
%%%----------------------------------------------------------------------

form_changepass_get(Host, Lang) ->
  HeadEls = [ 
             ?XAE(<<"meta">>,
                  [{<<"http-equiv">>, <<"Content-Type">>},
                   {<<"content">>,     <<"text/html; charset=utf-8">>}],
                  []),
             ?XCT(<<"title">>, ?T("Change Password")),
             ?XA(<<"link">>,
                 [{<<"href">>, <<"../register.css">>},
                  {<<"type">>, <<"text/css">>},
                  {<<"rel">>, <<"stylesheet">>}])],
  Els = [?XACT(<<"h1">>,
               [{<<"class">>, <<"title">>},
                {<<"style">>, <<"text-align:center;">>}],
               ?T("Change Password")),
         ?XAE(<<"form">>,
              [{<<"action">>, <<"">>}, {<<"method">>, <<"post">>}],
              [?XE(<<"ol">>,
                   [?XE(<<"li">>,
                        [?CT(?T("Username:")), ?C(<<" ">>),
                         ?INPUTS(<<"text">>, <<"username">>, <<"">>,
                                 <<"20">>)]),
                    ?XE(<<"li">>,
                        [?CT(?T("Server:")), ?C(<<" ">>),
                         ?INPUTS(<<"text">>, <<"host">>, Host, <<"20">>)]),
                    ?XE(<<"li">>,
                        [?CT(?T("Old Password:")), ?C(<<" ">>),
                         ?INPUTS(<<"password">>, <<"passwordold">>, <<"">>,
                                 <<"20">>)]),
                    ?XE(<<"li">>,
                        [?CT(?T("New Password:")), ?C(<<" ">>),
                         ?INPUTS(<<"password">>, <<"password">>, <<"">>,
                                 <<"20">>)]),
                    ?XE(<<"li">>,
                        [?CT(?T("Password Verification:")), ?C(<<" ">>),
                         ?INPUTS(<<"password">>, <<"password2">>, <<"">>,
                                 <<"20">>)]),
                    ?XE(<<"li">>,
                        [?INPUTT(<<"submit">>, <<"changepass">>,
                                 ?T("Change Password"))])])])],
  {200,
   [{<<"Server">>, <<"ejabberd">>},
    {<<"Content-Type">>, <<"text/html">>}],
   ejabberd_web:make_xhtml(HeadEls, Els)}.

%%%----------------------------------------------------------------------
%%% Formulary change password POST
%%%----------------------------------------------------------------------

form_changepass_post(Q) ->
    case catch get_changepass_parameters(Q) of
      [Username, Host, PasswordOld, Password, Password] ->
	  try_change_password(Username, Host, PasswordOld,
			      Password);
      [_Username, _Host, _PasswordOld, _Password, _Password2] ->
	  {error, passwords_not_identical};
      _ -> {error, wrong_parameters}
    end.

get_changepass_parameters(Q) ->
%% @spec(Username,Host,PasswordOld,Password) -> {atomic, ok} |
%%                                              {error, account_doesnt_exist} |
%%                                              {error, password_not_changed} |
%%                                              {error, password_incorrect}
    lists:map(fun (Key) ->
		      {value, {_Key, Value}} = lists:keysearch(Key, 1, Q),
		      Value
	      end,
	      [<<"username">>, <<"host">>, <<"passwordold">>, <<"password">>,
	       <<"password2">>]).

try_change_password(Username, Host, PasswordOld,
		    Password) ->
    try change_password(Username, Host, PasswordOld,
			Password)
    of
      {atomic, ok} -> {atomic, ok}
    catch
      error:{badmatch, Error} -> {error, Error}
    end.

change_password(Username, Host, PasswordOld,
		Password) ->
    account_exists = check_account_exists(Username, Host),
    password_correct = check_password(Username, Host,
				      PasswordOld),
    ok = ejabberd_auth:set_password(Username, Host,
				    Password),
    case check_password(Username, Host, Password) of
      password_correct -> {atomic, ok};
      password_incorrect -> {error, password_not_changed}
    end.

check_account_exists(Username, Host) ->
    case ejabberd_auth:user_exists(Username, Host) of
      true -> account_exists;
      false -> account_doesnt_exist
    end.

check_password(Username, Host, Password) ->
    case ejabberd_auth:check_password(Username, <<"">>, Host,
				      Password)
	of
      true -> password_correct;
      false -> password_incorrect
    end.

%%%----------------------------------------------------------------------
%%% Formulary delete account GET
%%%----------------------------------------------------------------------

form_del_get(Host, Lang) ->
  HeadEls = [ 
             ?XAE(<<"meta">>,
                  [{<<"http-equiv">>, <<"Content-Type">>},
                   {<<"content">>,     <<"text/html; charset=utf-8">>}],
                  []),
             ?XCT(<<"title">>,
                  ?T("Unregister an XMPP account")),
             ?XA(<<"link">>,
                 [{<<"href">>, <<"../register.css">>},
                  {<<"type">>, <<"text/css">>},
                  {<<"rel">>, <<"stylesheet">>}])],
  Els = [?XACT(<<"h1">>,
               [{<<"class">>, <<"title">>},
                {<<"style">>, <<"text-align:center;">>}],
               ?T("Unregister an XMPP account")),
         ?XCT(<<"p">>,
              ?T("This page allows to unregister an XMPP "
                 "account in this XMPP server.")),
         ?XAE(<<"form">>,
              [{<<"action">>, <<"">>}, {<<"method">>, <<"post">>}],
              [?XE(<<"ol">>,
                   [?XE(<<"li">>,
                        [?CT(?T("Username:")), ?C(<<" ">>),
                         ?INPUTS(<<"text">>, <<"username">>, <<"">>,
                                 <<"20">>)]),
                    ?XE(<<"li">>,
                        [?CT(?T("Server:")), ?C(<<" ">>),
                         ?INPUTS(<<"text">>, <<"host">>, Host, <<"20">>)]),
                    ?XE(<<"li">>,
                        [?CT(?T("Password:")), ?C(<<" ">>),
                         ?INPUTS(<<"password">>, <<"password">>, <<"">>,
                                 <<"20">>)]),
                    ?XE(<<"li">>,
                        [?INPUTT(<<"submit">>, <<"unregister">>,
                                 ?T("Unregister"))])])])],
  {200,
   [{<<"Server">>, <<"ejabberd">>},
    {<<"Content-Type">>, <<"text/html">>}],
   ejabberd_web:make_xhtml(HeadEls, Els)}.

%% @spec(Username, Host, Password, Ip) -> {success, ok, {Username, Host, Password} |
%%                                    {success, exists, {Username, Host, Password}} |
%%                                    {error, not_allowed} |
%%                                    {error, invalid_jid}
register_account(Username, Host, Password, Ip) ->
    try mod_register_opt:access(Host) of
	Access ->
	    case jid:make(Username, Host) of
		error -> {error, invalid_jid};
		JID ->
		    case acl:match_rule(Host, Access, JID) of
			deny -> {error, not_allowed};
			allow -> register_account2(Username, Host, Password, Ip)
		    end
	    end
    catch _:{module_not_loaded, mod_register, _Host} ->
	    {error, host_unknown}
    end.

register_account2(Username, Host, Password, Ip) ->
    case mod_register:try_register(Username, Host, Password, Ip, ?MODULE)
	of
      ok ->
	  {success, ok, {Username, Host, Password}};
      Other -> Other
    end.

%%%----------------------------------------------------------------------
%%% Formulary delete POST
%%%----------------------------------------------------------------------

form_del_post(Q) ->
    case catch get_unregister_parameters(Q) of
      [Username, Host, Password] ->
	  try_unregister_account(Username, Host, Password);
      _ -> {error, wrong_parameters}
    end.

get_unregister_parameters(Q) ->
%% @spec(Username, Host, Password) -> {atomic, ok} |
%%                                    {error, account_doesnt_exist} |
%%                                    {error, account_exists} |
%%                                    {error, password_incorrect}
    lists:map(fun (Key) ->
		      {value, {_Key, Value}} = lists:keysearch(Key, 1, Q),
		      Value
	      end,
	      [<<"username">>, <<"host">>, <<"password">>]).

try_unregister_account(Username, Host, Password) ->
    try unregister_account(Username, Host, Password) of
      {atomic, ok} -> {atomic, ok}
    catch
      error:{badmatch, Error} -> {error, Error}
    end.

unregister_account(Username, Host, Password) ->
    account_exists = check_account_exists(Username, Host),
    password_correct = check_password(Username, Host,
				      Password),
    ok = ejabberd_auth:remove_user(Username, Host,
				   Password),
    account_doesnt_exist = check_account_exists(Username,
						Host),
    {atomic, ok}.

%%%----------------------------------------------------------------------
%%% Error texts
%%%----------------------------------------------------------------------

get_error_text({error, captcha_non_valid}) ->
    ?T("The captcha you entered is wrong");
get_error_text({error, exists}) ->
    ?T("The account already exists");
get_error_text({error, password_incorrect}) ->
    ?T("Incorrect password");
get_error_text({error, host_unknown}) ->
    ?T("Host unknown");
get_error_text({error, account_doesnt_exist}) ->
    ?T("Account doesn't exist");
get_error_text({error, account_exists}) ->
    ?T("The account was not unregistered");
get_error_text({error, password_not_changed}) ->
    ?T("The password was not changed");
get_error_text({error, passwords_not_identical}) ->
    ?T("The passwords are different");
get_error_text({error, wrong_parameters}) ->
    ?T("Wrong parameters in the web formulary");
get_error_text({error, Why}) ->
    mod_register:format_error(Why).

mod_options(_) ->
    [].

mod_doc() ->
    #{desc =>
          [?T("This module provides a web page where users can:"), "",
           ?T("- Register a new account on the server."), "",
           ?T("- Change the password from an existing account on the server."), "",
           ?T("- Unregister an existing account on the server."), "",
	   ?T("This module supports _`basic.md#captcha|CAPTCHA`_ "
              "to register a new account. "
	      "To enable this feature, configure the "
              "top-level _`captcha_cmd`_ and "
	      "top-level _`captcha_url`_ options."), "",
	   ?T("As an example usage, the users of the host 'localhost' can "
	      "visit the page: 'https://localhost:5280/register/' It is "
	      "important to include the last / character in the URL, "
	      "otherwise the subpages URL will be incorrect."), "",
           ?T("This module is enabled in 'listen' -> 'ejabberd_http' -> "
              "_`listen-options.md#request_handlers|request_handlers`_, "
              "no need to enable in 'modules'."),
           ?T("The module depends on _`mod_register`_ where all the "
              "configuration is performed.")],
     example =>
         ["listen:",
          "  -",
          "    port: 5280",
          "    module: ejabberd_http",
          "    request_handlers:",
          "      /register: mod_register_web",
          "",
          "modules:",
          "  mod_register: {}"]}.
