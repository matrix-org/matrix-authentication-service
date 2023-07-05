// Copyright 2023 The Matrix.org Foundation C.I.C.
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
    extract::State,
    response::{Html, IntoResponse},
};
use mas_axum_utils::FancyError;
use mas_templates::{AppContext, Templates};

#[tracing::instrument(name = "handlers.views.app.get", skip_all, err)]
pub async fn get(State(templates): State<Templates>) -> Result<impl IntoResponse, FancyError> {
    // XXX: should we redirect from here if the user is not logged in?
    let ctx = AppContext::default();
    let content = templates.render_app(&ctx).await?;

    Ok(Html(content))
}
