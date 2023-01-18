// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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
use mas_data_model::{User, UserEmail, UserEmailVerification};
use rand::RngCore;
use ulid::Ulid;

use crate::{pagination::Page, Clock, Pagination};

#[async_trait]
pub trait UserEmailRepository: Send + Sync {
    type Error;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserEmail>, Self::Error>;
    async fn find(&mut self, user: &User, email: &str) -> Result<Option<UserEmail>, Self::Error>;
    async fn get_primary(&mut self, user: &User) -> Result<Option<UserEmail>, Self::Error>;

    async fn all(&mut self, user: &User) -> Result<Vec<UserEmail>, Self::Error>;
    async fn list_paginated(
        &mut self,
        user: &User,
        pagination: Pagination,
    ) -> Result<Page<UserEmail>, Self::Error>;
    async fn count(&mut self, user: &User) -> Result<usize, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        user: &User,
        email: String,
    ) -> Result<UserEmail, Self::Error>;
    async fn remove(&mut self, user_email: UserEmail) -> Result<(), Self::Error>;

    async fn mark_as_verified(
        &mut self,
        clock: &Clock,
        user_email: UserEmail,
    ) -> Result<UserEmail, Self::Error>;

    async fn set_as_primary(&mut self, user_email: &UserEmail) -> Result<(), Self::Error>;

    async fn add_verification_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &Clock,
        user_email: &UserEmail,
        max_age: chrono::Duration,
        code: String,
    ) -> Result<UserEmailVerification, Self::Error>;

    async fn find_verification_code(
        &mut self,
        clock: &Clock,
        user_email: &UserEmail,
        code: &str,
    ) -> Result<Option<UserEmailVerification>, Self::Error>;

    async fn consume_verification_code(
        &mut self,
        clock: &Clock,
        verification: UserEmailVerification,
    ) -> Result<UserEmailVerification, Self::Error>;
}
