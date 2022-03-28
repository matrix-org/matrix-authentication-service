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
    response::{Html, IntoResponse, Redirect, Response},
};
use hyper::http::uri::{Parts, PathAndQuery, Uri};
use mas_axum_utils::{
    csrf::{CsrfExt, ProtectedForm},
    fancy_error, FancyError, PrivateCookieJar, SessionInfoExt,
};
use mas_config::Encrypter;
use mas_data_model::errors::WrapFormError;
use mas_storage::user::login;
use mas_templates::{LoginContext, LoginFormField, TemplateContext, Templates};
use serde::Deserialize;
use sqlx::PgPool;

use super::{shared::PostAuthAction, RegisterRequest};

#[derive(Deserialize, Default)]
pub(crate) struct LoginRequest {
    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,
}

impl From<PostAuthAction> for LoginRequest {
    fn from(post_auth_action: PostAuthAction) -> Self {
        Some(post_auth_action).into()
    }
}

impl From<Option<PostAuthAction>> for LoginRequest {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

impl LoginRequest {
    pub fn build_uri(&self) -> anyhow::Result<Uri> {
        let path_and_query = if let Some(next) = &self.post_auth_action {
            let qs = serde_urlencoded::to_string(next)?;
            PathAndQuery::try_from(format!("/login?{}", qs))?
        } else {
            PathAndQuery::from_static("/login")
        };
        let uri = Uri::from_parts({
            let mut parts = Parts::default();
            parts.path_and_query = Some(path_and_query);
            parts
        })?;
        Ok(uri)
    }

    fn redirect(self) -> Result<impl IntoResponse, anyhow::Error> {
        let uri = if let Some(action) = self.post_auth_action {
            action.build_uri()?
        } else {
            Uri::from_static("/")
        };

        Ok(Redirect::to(uri))
    }
}

#[derive(Deserialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

pub(crate) async fn get(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<LoginRequest>,
    cookie_jar: PrivateCookieJar<Encrypter>,
) -> Result<Response, FancyError> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(fancy_error(templates.clone()))?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info
        .load_session(&mut conn)
        .await
        .map_err(fancy_error(templates.clone()))?;

    if maybe_session.is_some() {
        let response = query
            .redirect()
            .map_err(fancy_error(templates.clone()))?
            .into_response();
        Ok(response)
    } else {
        let ctx = LoginContext::default();
        let ctx = match query.post_auth_action {
            Some(next) => {
                let register_link = RegisterRequest::from(next.clone())
                    .build_uri()
                    .map_err(fancy_error(templates.clone()))?;
                let next = next
                    .load_context(&mut conn)
                    .await
                    .map_err(fancy_error(templates.clone()))?;
                ctx.with_post_action(next)
                    .with_register_link(register_link.to_string())
            }
            None => ctx,
        };
        let ctx = ctx.with_csrf(csrf_token.form_value());

        let content = templates
            .render_login(&ctx)
            .await
            .map_err(fancy_error(templates.clone()))?;

        Ok((cookie_jar.headers(), Html(content)).into_response())
    }
}

pub(crate) async fn post(
    Extension(templates): Extension<Templates>,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<LoginRequest>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, FancyError> {
    use mas_storage::user::LoginError;
    let mut conn = pool
        .acquire()
        .await
        .map_err(fancy_error(templates.clone()))?;

    let form = cookie_jar
        .verify_form(form)
        .map_err(fancy_error(templates.clone()))?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token();

    // TODO: recover
    match login(&mut conn, &form.username, form.password).await {
        Ok(session_info) => {
            let cookie_jar = cookie_jar.set_session(&session_info);
            let reply = query.redirect().map_err(fancy_error(templates.clone()))?;
            Ok((cookie_jar.headers(), reply).into_response())
        }
        Err(e) => {
            let errored_form = match e {
                LoginError::NotFound { .. } => e.on_field(LoginFormField::Username),
                LoginError::Authentication { .. } => e.on_field(LoginFormField::Password),
                LoginError::Other(_) => e.on_form(),
            };
            let ctx = LoginContext::default()
                .with_form_error(errored_form)
                .with_csrf(csrf_token.form_value());

            let content = templates
                .render_login(&ctx)
                .await
                .map_err(fancy_error(templates.clone()))?;

            Ok((cookie_jar.headers(), Html(content)).into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_login_request() {
        let res: Result<LoginRequest, _> =
            serde_urlencoded::from_str("next=continue_authorization_grant&data=13");
        res.unwrap().post_auth_action.unwrap();
    }
}
