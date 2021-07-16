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

use anyhow::Context;
use argon2::Argon2;
use password_hash::{PasswordHash, SaltString};
use rand::rngs::OsRng;
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use tracing::{info_span, Instrument};

#[derive(Serialize, Debug, Clone, FromRow)]
pub struct User {
    id: i32,
    username: String,
}

impl User {
    pub fn key(&self) -> i32 {
        self.id
    }
}

impl super::Storage<PgPool> {
    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<User> {
        let mut conn = self.pool.acquire().await?;

        let (id, username, hashed_password): (i32, String, String) = sqlx::query_as(
            r#"
                SELECT id, username, hashed_password
                FROM users
                WHERE username = $1
            "#,
        )
        .bind(&username)
        .fetch_one(&mut conn)
        .instrument(info_span!("Fetch user"))
        .await
        .context("could not find user")?;

        let context = Argon2::default();
        let hasher = PasswordHash::new(&hashed_password).map_err(anyhow::Error::msg)?;
        hasher
            .verify_password(&[&context], &password)
            .map_err(anyhow::Error::msg)?;

        Ok(User { id, username })
    }

    pub async fn register_user(&self, username: &str, password: &str) -> anyhow::Result<User> {
        let context = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let hashed_password =
            PasswordHash::generate(context, password, salt.as_str()).map_err(anyhow::Error::msg)?;

        let mut conn = self.pool.acquire().await?;

        let result: (i32,) = sqlx::query_as(
            r#"
                INSERT INTO users (username, hashed_password)
                VALUES ($1, $2)
                RETURNING id
            "#,
        )
        .bind(&username)
        .bind(&hashed_password.to_string())
        .fetch_one(&mut conn)
        .instrument(info_span!("Register user"))
        .await
        .context("could not insert user")?;

        Ok(User {
            id: result.0,
            username: username.to_string(),
        })
    }

    pub async fn lookup_user(&self, id: i32) -> anyhow::Result<User> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query_as(
            r#"
                SELECT id, username
                FROM users
                WHERE id = $1
            "#,
        )
        .bind(&id)
        .fetch_one(&mut conn)
        .instrument(info_span!("Fetch user"))
        .await
        .context("could not fetch user")
    }
}
