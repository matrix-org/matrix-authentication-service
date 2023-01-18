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

use async_trait::async_trait;
use mas_data_model::{CompatSession, Device, User};
use rand::RngCore;
use ulid::Ulid;

use crate::Clock;

#[async_trait]
pub trait CompatSessionRepository: Send + Sync {
    type Error;

    /// Lookup a compat session by its ID
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error>;

    /// Start a new compat session
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
    ) -> Result<CompatSession, Self::Error>;

    /// End a compat session
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error>;
}
