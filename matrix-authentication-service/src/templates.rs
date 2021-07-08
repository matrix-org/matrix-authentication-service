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

use csrf::CsrfToken;
use tera::{Context, Tera};
use tide::Request;
use tracing::info;

use crate::state::State;

pub fn load() -> Result<Tera, tera::Error> {
    let path = format!("{}/templates/**/*.{{html,txt}}", env!("CARGO_MANIFEST_DIR"));
    info!(%path, "Loading templates");
    Tera::new(&path)
}

pub async fn common_context(req: &Request<State>) -> Result<Context, anyhow::Error> {
    let state = req.state();
    let session = req.session();

    let mut ctx = Context::new();

    let user: Option<String> = session.get("current_user");
    if let Some(ref user) = user {
        let user = state.storage().lookup_user(user).await?;
        ctx.insert("current_user", &user);
    }

    let token: Option<&CsrfToken> = req.ext();
    if let Some(token) = token {
        ctx.insert("csrf_token", &token.b64_string());
    }

    Ok(ctx)
}
