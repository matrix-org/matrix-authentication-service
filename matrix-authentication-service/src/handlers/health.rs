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

use sqlx::PgPool;
use tracing::{info_span, Instrument};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

use crate::{errors::WrapError, filters::with_pool};

pub fn filter(pool: PgPool) -> BoxedFilter<(impl Reply,)> {
    warp::get()
        .and(warp::path("health"))
        .and(with_pool(pool))
        .and_then(get)
        .boxed()
}

async fn get(pool: PgPool) -> Result<impl Reply, Rejection> {
    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&pool)
        .instrument(info_span!("DB health"))
        .await
        .wrap_error()?;

    Ok(Box::new("ok"))
}
