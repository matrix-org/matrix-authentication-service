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

//! Database-related tasks

use sqlx::{Pool, Postgres};
use tracing::{debug, error, info};

use super::Task;

#[derive(Clone)]
struct CleanupExpired(Pool<Postgres>);

impl std::fmt::Debug for CleanupExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CleanupExpired").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl Task for CleanupExpired {
    async fn run(&self) {
        let res = mas_storage::oauth2::access_token::cleanup_expired(&self.0).await;
        match res {
            Ok(0) => {
                debug!("no token to clean up");
            }
            Ok(count) => {
                info!(count, "cleaned up expired tokens");
            }
            Err(error) => {
                error!(?error, "failed to cleanup expired tokens");
            }
        }
    }
}

/// Cleanup expired tokens
#[must_use]
pub fn cleanup_expired(pool: &Pool<Postgres>) -> impl Task + Clone {
    CleanupExpired(pool.clone())
}
