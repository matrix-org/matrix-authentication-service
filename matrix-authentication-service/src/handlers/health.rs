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

use hyper::header::CONTENT_TYPE;
use mime::TEXT_PLAIN;
use sqlx::PgPool;
use tracing::{info_span, Instrument};
use warp::{reply::with_header, Filter, Rejection, Reply};

use crate::{errors::WrapError, filters::with_pool};

pub fn filter(
    pool: &PgPool,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::get()
        .and(warp::path("health"))
        .and(with_pool(pool))
        .and_then(get)
}

async fn get(pool: PgPool) -> Result<impl Reply, Rejection> {
    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&pool)
        .instrument(info_span!("DB health"))
        .await
        .wrap_error()?;

    Ok(with_header("ok", CONTENT_TYPE, TEXT_PLAIN.to_string()))
}
