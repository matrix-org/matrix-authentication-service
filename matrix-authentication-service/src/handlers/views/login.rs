// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::sync::Arc;

use serde::Deserialize;
use sqlx::PgPool;
use tera::Tera;
use warp::{reply::with_header, Rejection, Reply};

use crate::{errors::WrapError, filters::CsrfToken, templates::CommonContext};

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

pub async fn get(
    templates: Arc<Tera>,
    csrf_token: CsrfToken,
    db: PgPool,
) -> Result<(CsrfToken, impl Reply), Rejection> {
    let ctx = CommonContext::default()
        .with_csrf_token(&csrf_token)
        .with_session(&db)
        .await
        .wrap_error()?
        .finish()
        .wrap_error()?;

    // TODO: check if there is an existing session
    let content = templates.render("login.html", &ctx).wrap_error()?;
    Ok((
        csrf_token,
        with_header(content, "Content-Type", "text/html"),
    ))
}

/*
pub async fn post(mut req: Request<State>) -> tide::Result {
    let form: CsrfForm<LoginForm> = req.body_form().await?;
    let form = form.verify_csrf(&req)?;
    let state = req.state();

    let session_info = state
        .storage()
        .login(&form.username, &form.password)
        .await?;

    let session = req.session_mut();
    session.insert("current_session", session_info.key())?;

    Ok(Redirect::new("/").into())
}
*/
