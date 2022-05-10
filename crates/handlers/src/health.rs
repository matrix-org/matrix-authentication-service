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

use axum::{extract::Extension, response::IntoResponse};
use mas_axum_utils::FancyError;
use sqlx::PgPool;
use tracing::{info_span, Instrument};

pub async fn get(Extension(pool): Extension<PgPool>) -> Result<impl IntoResponse, FancyError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&mut conn)
        .instrument(info_span!("DB health"))
        .await?;

    Ok("ok")
}
