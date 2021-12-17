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

//! Database-related filters to grab connections and start transactions from the
//! connection pool

use std::convert::Infallible;

use sqlx::{
    pool::{Pool, PoolConnection},
    Database, Transaction,
};
use warp::{Filter, Rejection};

use crate::errors::WrapError;

fn with_pool<T: Database>(
    pool: &Pool<T>,
) -> impl Filter<Extract = (Pool<T>,), Error = Infallible> + Clone + Send + Sync + 'static {
    let pool = pool.clone();
    warp::any().map(move || pool.clone())
}

/// Acquire a connection to the database
pub fn connection<T: Database>(
    pool: &Pool<T>,
) -> impl Filter<Extract = (PoolConnection<T>,), Error = Rejection> + Clone + Send + Sync + 'static
{
    with_pool(pool).and_then(acquire_connection)
}

async fn acquire_connection<T: Database>(pool: Pool<T>) -> Result<PoolConnection<T>, Rejection> {
    let conn = pool.acquire().await.wrap_error()?;
    Ok(conn)
}

/// Start a database transaction
pub fn transaction<T: Database>(
    pool: &Pool<T>,
) -> impl Filter<Extract = (Transaction<'static, T>,), Error = Rejection> + Clone + Send + Sync + 'static
{
    with_pool(pool).and_then(acquire_transaction)
}

async fn acquire_transaction<T: Database>(
    pool: Pool<T>,
) -> Result<Transaction<'static, T>, Rejection> {
    let txn = pool.begin().await.wrap_error()?;
    Ok(txn)
}
