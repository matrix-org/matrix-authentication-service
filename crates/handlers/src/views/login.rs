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
    extract::{Extension, Form, Query},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use mas_axum_utils::{
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_config::Encrypter;
use mas_router::Route;
use mas_storage::user::{login, LoginError};
use mas_templates::{
    FieldError, FormError, LoginContext, LoginFormField, TemplateContext, Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};

use super::shared::OptionalPostAuthAction;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

#[tracing::instrument(skip(templates, pool, cookie_jar))]
pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool.acquire().await?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut conn).await?;

    if maybe_session.is_some() {
        let reply = query.go_next();
        Ok((cookie_jar, reply).into_response())
    } else {
        let content = render(
            LoginContext::default(),
            query,
            csrf_token,
            &mut conn,
            &templates,
        )
        .await?;

        Ok((cookie_jar, Html(content)).into_response())
    }
}

pub(crate) async fn post(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, FancyError> {
    let mut conn = pool.acquire().await?;

    let form = cookie_jar.verify_form(form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();

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
        let content = render(
            LoginContext::default().with_form_state(state),
            query,
            csrf_token,
            &mut conn,
            &templates,
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    match login(&mut conn, &form.username, &form.password).await {
        Ok(session_info) => {
            let cookie_jar = cookie_jar.set_session(&session_info);
            let reply = query.go_next();
            Ok((cookie_jar, reply).into_response())
        }
        Err(e) => {
            let state = match e {
                LoginError::NotFound { .. } | LoginError::Authentication { .. } => {
                    state.with_error_on_form(FormError::InvalidCredentials)
                }
                LoginError::Other(_) => state.with_error_on_form(FormError::Internal),
            };

            let content = render(
                LoginContext::default().with_form_state(state),
                query,
                csrf_token,
                &mut conn,
                &templates,
            )
            .await?;

            Ok((cookie_jar, Html(content)).into_response())
        }
    }
}

async fn render(
    ctx: LoginContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    conn: &mut PgConnection,
    templates: &Templates,
) -> Result<String, FancyError> {
    let next = action.load_context(conn).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let register_link = mas_router::Register::from(action.post_auth_action).relative_url();
    let ctx = ctx
        .with_register_link(register_link.to_string())
        .with_csrf(csrf_token.form_value());

    let content = templates.render_login(&ctx).await?;
    Ok(content)
}
