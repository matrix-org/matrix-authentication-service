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

use axum::{extract::State, response::IntoResponse};
use mas_axum_utils::FancyError;
use sqlx::PgPool;
use tracing::{info_span, Instrument};

pub async fn get(State(pool): State<PgPool>) -> Result<impl IntoResponse, FancyError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&mut conn)
        .instrument(info_span!("DB health"))
        .await?;

    Ok("ok")
}

#[cfg(test)]
mod tests {
    use hyper::{Body, Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    #[sqlx::test(migrator = "mas_storage::MIGRATOR")]
    async fn test_get_health(pool: PgPool) -> Result<(), anyhow::Error> {
        let state = crate::test_state(pool).await?;
        let app = crate::router(state);

        let request = Request::builder().uri("/health").body(Body::empty())?;

        let response = app.oneshot(request).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await?;
        assert_eq!(body, "ok");

        Ok(())
    }
}
