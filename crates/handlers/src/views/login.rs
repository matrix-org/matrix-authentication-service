// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
    TypedHeader,
};
use headers::UserAgent;
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::BrowserSession;
use mas_i18n::DataLocale;
use mas_router::{UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserPasswordRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess,
};
use mas_templates::{
    FieldError, FormError, LoginContext, LoginFormField, TemplateContext, Templates, ToFormState,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::{passwords::PasswordManager, BoundActivityTracker, PreferredLanguage};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

#[tracing::instrument(name = "handlers.views.login.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    };

    let providers = repo.upstream_oauth_provider().all().await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
    if !password_manager.is_enabled() && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        };

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    };

    let content = render(
        locale,
        LoginContext::default()
            // XXX: we might want to have a site-wide config in the templates context instead?
            .with_password_login(password_manager.is_enabled())
            .with_upstream_providers(providers),
        query,
        csrf_token,
        &mut repo,
        &templates,
    )
    .await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.login.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<UserAgent>>,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, FancyError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    if !password_manager.is_enabled() {
        // XXX: is it necessary to have better errors here?
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the form
    let state = {
        let mut state = form.to_form_state();

        if form.username.is_empty() {
            state.add_error_on_field(LoginFormField::Username, FieldError::Required);
        }

        if form.password.is_empty() {
            state.add_error_on_field(LoginFormField::Password, FieldError::Required);
        }

        state
    };

    if !state.is_valid() {
        let providers = repo.upstream_oauth_provider().all().await?;
        let content = render(
            locale,
            LoginContext::default()
                .with_form_state(state)
                .with_upstream_providers(providers),
            query,
            csrf_token,
            &mut repo,
            &templates,
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    match login(
        password_manager,
        &mut repo,
        rng,
        &clock,
        &form.username,
        &form.password,
        user_agent,
    )
    .await
    {
        Ok(session_info) => {
            repo.save().await?;

            activity_tracker
                .record_browser_session(&clock, &session_info)
                .await;

            let cookie_jar = cookie_jar.set_session(&session_info);
            let reply = query.go_next(&url_builder);
            Ok((cookie_jar, reply).into_response())
        }
        Err(e) => {
            let state = state.with_error_on_form(e);

            let content = render(
                locale,
                LoginContext::default().with_form_state(state),
                query,
                csrf_token,
                &mut repo,
                &templates,
            )
            .await?;

            Ok((cookie_jar, Html(content)).into_response())
        }
    }
}

// TODO: move that logic elsewhere?
async fn login(
    password_manager: PasswordManager,
    repo: &mut impl RepositoryAccess,
    mut rng: impl Rng + CryptoRng + Send,
    clock: &impl Clock,
    username: &str,
    password: &str,
    user_agent: Option<String>,
) -> Result<BrowserSession, FormError> {
    // XXX: we're loosing the error context here
    // First, lookup the user
    let user = repo
        .user()
        .find_by_username(username)
        .await
        .map_err(|_e| FormError::Internal)?
        .filter(mas_data_model::User::is_valid)
        .ok_or(FormError::InvalidCredentials)?;

    // And its password
    let user_password = repo
        .user_password()
        .active(&user)
        .await
        .map_err(|_e| FormError::Internal)?
        .ok_or(FormError::InvalidCredentials)?;

    let password = Zeroizing::new(password.as_bytes().to_vec());

    // Verify the password, and upgrade it on-the-fly if needed
    let new_password_hash = password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await
        .map_err(|_| FormError::InvalidCredentials)?;

    let user_password = if let Some((version, new_password_hash)) = new_password_hash {
        // Save the upgraded password
        repo.user_password()
            .add(
                &mut rng,
                clock,
                &user,
                version,
                new_password_hash,
                Some(&user_password),
            )
            .await
            .map_err(|_| FormError::Internal)?
    } else {
        user_password
    };

    // Start a new session
    let user_session = repo
        .browser_session()
        .add(&mut rng, clock, &user, user_agent)
        .await
        .map_err(|_| FormError::Internal)?;

    // And mark it as authenticated by the password
    repo.browser_session()
        .authenticate_with_password(&mut rng, clock, &user_session, &user_password)
        .await
        .map_err(|_| FormError::Internal)?;

    Ok(user_session)
}

async fn render(
    locale: DataLocale,
    ctx: LoginContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut impl RepositoryAccess,
    templates: &Templates,
) -> Result<String, FancyError> {
    let next = action.load_context(repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_login(&ctx)?;
    Ok(content)
}

#[cfg(test)]
mod test {
    use hyper::{
        header::{CONTENT_TYPE, LOCATION},
        Request, StatusCode,
    };
    use mas_data_model::UpstreamOAuthProviderClaimsImports;
    use mas_iana::oauth::OAuthClientAuthenticationMethod;
    use mas_router::Route;
    use mas_storage::{
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
        RepositoryAccess,
    };
    use mas_templates::escape_html;
    use oauth2_types::scope::OPENID;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        passwords::PasswordManager,
        test_utils::{init_tracing, CookieHelper, RequestBuilderExt, ResponseExt, TestState},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        init_tracing();
        let state = {
            let mut state = TestState::from_pool(pool).await.unwrap();
            state.password_manager = PasswordManager::disabled();
            state
        };
        let mut rng = state.rng();

        // Without password login and no upstream providers, we should get an error
        // message
        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("No login methods available"));

        // Adding an upstream provider should redirect to it
        let mut repo = state.repository().await.unwrap();
        let first_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: "https://first.com/".to_owned(),
                    human_name: Some("First Ltd.".to_owned()),
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: OAuthClientAuthenticationMethod::None,
                    token_endpoint_signing_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first_provider_login = mas_router::UpstreamOAuth2Authorize::new(first_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &first_provider_login.path_and_query());

        // Adding a second provider should show a login page with both providers
        let mut repo = state.repository().await.unwrap();
        let second_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: "https://second.com/".to_owned(),
                    human_name: Some("Second Ltd.".to_owned()),
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: OAuthClientAuthenticationMethod::None,
                    token_endpoint_signing_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second_provider_login = mas_router::UpstreamOAuth2Authorize::new(second_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains(&escape_html("First Ltd.")));
        assert!(response
            .body()
            .contains(&escape_html(&first_provider_login.path_and_query())));
        assert!(response.body().contains(&escape_html("Second Ltd.")));
        assert!(response
            .body()
            .contains(&escape_html(&second_provider_login.path_and_query())));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login(pool: PgPool) {
        init_tracing();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new("hunter2".as_bytes().to_vec()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }
}
