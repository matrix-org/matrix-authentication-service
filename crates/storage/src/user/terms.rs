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
use rand_core::RngCore;
use url::Url;

use crate::{repository_impl, Clock};

/// A [`UserTermsRepository`] helps interacting with the terms of service agreed
/// by a [`User`]
#[async_trait]
pub trait UserTermsRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Accept the terms of service by a [`User`]
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator used to generate IDs
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The [`User`] accepting the terms
    /// * `terms_url`: The URL of the terms of service the user is accepting
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error>;
}

repository_impl!(UserTermsRepository:
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error>;
);
