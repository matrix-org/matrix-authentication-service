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
};
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::BrowserSession;
use mas_router::{Route, UpstreamOAuth2Authorize};
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
use crate::passwords::PasswordManager;

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
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    if maybe_session.is_some() {
        let reply = query.go_next();
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

        return Ok((cookie_jar, destination.go()).into_response());
    };

    let content = render(
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
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, FancyError> {
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
    )
    .await
    {
        Ok(session_info) => {
            repo.save().await?;

            let cookie_jar = cookie_jar.set_session(&session_info);
            let reply = query.go_next();
            Ok((cookie_jar, reply).into_response())
        }
        Err(e) => {
            let state = state.with_error_on_form(e);

            let content = render(
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
        .add(&mut rng, clock, &user)
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
    let ctx = ctx.with_csrf(csrf_token.form_value());

    let content = templates.render_login(&ctx).await?;
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
    use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, RepositoryAccess};
    use mas_templates::escape_html;
    use oauth2_types::scope::OPENID;
    use sqlx::PgPool;

    use crate::{
        passwords::PasswordManager,
        test_utils::{init_tracing, RequestBuilderExt, ResponseExt, TestState},
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
        assert!(response.body().contains("No login method available"));

        // Adding an upstream provider should redirect to it
        let mut repo = state.repository().await.unwrap();
        let first_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                "https://first.com/".into(),
                [OPENID].into_iter().collect(),
                OAuthClientAuthenticationMethod::None,
                None,
                "first_client".into(),
                None,
                UpstreamOAuthProviderClaimsImports::default(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first_provider_login = mas_router::UpstreamOAuth2Authorize::new(first_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &first_provider_login.relative_url());

        // Adding a second provider should show a login page with both providers
        let mut repo = state.repository().await.unwrap();
        let second_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                "https://second.com/".into(),
                [OPENID].into_iter().collect(),
                OAuthClientAuthenticationMethod::None,
                None,
                "second_client".into(),
                None,
                UpstreamOAuthProviderClaimsImports::default(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second_provider_login = mas_router::UpstreamOAuth2Authorize::new(second_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response
            .body()
            .contains(&escape_html(&first_provider.issuer)));
        assert!(response
            .body()
            .contains(&escape_html(&first_provider_login.relative_url())));
        assert!(response
            .body()
            .contains(&escape_html(&second_provider.issuer)));
        assert!(response
            .body()
            .contains(&escape_html(&second_provider_login.relative_url())));
    }
}
