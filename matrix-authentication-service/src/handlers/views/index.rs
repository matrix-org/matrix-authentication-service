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

use tide::{Request, Response};

use crate::{state::State, templates::common_context};

pub async fn get(req: Request<State>) -> tide::Result {
    let state = req.state();
    let ctx = common_context(&req).await?;

    let content = state.templates().render("index.html", &ctx)?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}
