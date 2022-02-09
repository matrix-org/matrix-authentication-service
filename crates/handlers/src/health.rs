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
use mas_warp_utils::{
    errors::WrapError,
    filters::{self, database::connection},
};
use mime::TEXT_PLAIN;
use sqlx::{pool::PoolConnection, PgPool, Postgres};
use tracing::{info_span, Instrument};
use warp::{filters::BoxedFilter, reply::with_header, Filter, Rejection, Reply};

pub fn filter(pool: &PgPool) -> BoxedFilter<(Box<dyn Reply>,)> {
    warp::path!("health")
        .and(filters::trace::name("GET /health"))
        .and(warp::get())
        .and(connection(pool))
        .and_then(get)
        .boxed()
}

async fn get(mut conn: PoolConnection<Postgres>) -> Result<Box<dyn Reply>, Rejection> {
    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&mut conn)
        .instrument(info_span!("DB health"))
        .await
        .wrap_error()?;

    Ok(Box::new(with_header(
        "ok",
        CONTENT_TYPE,
        TEXT_PLAIN.to_string(),
    )))
}
