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

use sqlx::PgPool;
use tera::Tera;
use warp::{reply::with_header, Rejection, Reply};

use crate::{errors::WrapError, filters::CsrfToken, templates::CommonContext};

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

    let content = templates.render("index.html", &ctx).wrap_error()?;
    Ok((
        csrf_token,
        with_header(content, "Content-Type", "text/html"),
    ))
}
