// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use mas_data_model::SiteConfig;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_storage::{BoxClock, BoxRepository, BoxRng, RepositoryError};

use crate::Requester;

#[async_trait::async_trait]
pub trait State {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError>;
    async fn policy(&self) -> Result<Policy, mas_policy::InstantiateError>;
    fn homeserver_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error>;
    fn clock(&self) -> BoxClock;
    fn rng(&self) -> BoxRng;
    fn site_config(&self) -> &SiteConfig;
}

pub type BoxState = Box<dyn State + Send + Sync + 'static>;

pub trait ContextExt {
    fn state(&self) -> &BoxState;

    fn requester(&self) -> &Requester;
}

impl ContextExt for async_graphql::Context<'_> {
    fn state(&self) -> &BoxState {
        self.data_unchecked()
    }

    fn requester(&self) -> &Requester {
        self.data_unchecked()
    }
}
