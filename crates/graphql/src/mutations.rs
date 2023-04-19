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

use async_graphql::{Context, Object, ID};
use mas_storage::{
    job::{JobRepositoryExt, VerifyEmailJob},
    user::UserEmailRepository,
    BoxClock, BoxRepository, BoxRng, RepositoryAccess, SystemClock,
};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use tokio::sync::Mutex;

use crate::model::{NodeType, UserEmail};

struct RootMutations;

fn clock_and_rng() -> (BoxClock, BoxRng) {
    // XXX: this should be moved somewhere else
    let clock = SystemClock::default();
    let rng = ChaChaRng::from_entropy();
    (Box::new(clock), Box::new(rng))
}

#[Object]
impl RootMutations {
    async fn add_email(
        &self,
        ctx: &Context<'_>,
        email: String,
        user_id: ID,
    ) -> Result<UserEmail, async_graphql::Error> {
        let id = NodeType::User.extract_ulid(&user_id)?;
        let session = ctx.data_opt::<mas_data_model::BrowserSession>().cloned();
        let (clock, mut rng) = clock_and_rng();
        let mut repo = ctx.data::<Mutex<BoxRepository>>()?.lock().await;

        let Some(session) = session else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        if session.user.id != id {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let user_email = repo
            .user_email()
            .add(&mut rng, &clock, &session.user, email)
            .await?;

        repo.job()
            .schedule_job(VerifyEmailJob::new(&user_email))
            .await?;
        // TODO: how do we save the transaction here?

        Ok(UserEmail(user_email))
    }
}
