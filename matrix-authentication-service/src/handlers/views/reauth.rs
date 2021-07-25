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

use serde::Deserialize;
use tide::{Redirect, Request, Response};

use crate::{csrf::CsrfForm, state::State, templates::common_context};

#[derive(Deserialize)]
struct ReauthForm {
    password: String,
}

pub async fn get(req: Request<State>) -> tide::Result {
    let state = req.state();
    let ctx = common_context(&req).await?;

    // TODO: check if there is an existing session
    let content = state.templates().render("reauth.html", &ctx)?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}

pub async fn post(mut req: Request<State>) -> tide::Result {
    let form: CsrfForm<ReauthForm> = req.body_form().await?;
    let form = form.verify_csrf(&req)?;
    let state = req.state();
    let session = req.session();

    let session_id = session
        .get("current_session")
        .ok_or_else(|| anyhow::anyhow!("could not find existing session"))?;

    let _session = state
        .storage()
        .lookup_and_reauth_session(session_id, &form.password)
        .await?;

    Ok(Redirect::new("/").into())
}
