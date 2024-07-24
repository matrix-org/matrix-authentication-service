// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use async_trait::async_trait;
use mas_data_model::User;
use mas_storage::{user::UserTermsRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError};

/// An implementation of [`UserTermsRepository`] for a PostgreSQL connection
pub struct PgUserTermsRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserTermsRepository<'c> {
    /// Create a new [`PgUserTermsRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl<'c> UserTermsRepository for PgUserTermsRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_terms.accept_terms",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_terms.id,
            %user_terms.url = terms_url.as_str(),
        ),
        err,
    )]
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_terms.id", tracing::field::display(id));

        sqlx::query!(
            r#"
            INSERT INTO user_terms (user_terms_id, user_id, terms_url, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, terms_url) DO NOTHING
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            terms_url.as_str(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }
}
