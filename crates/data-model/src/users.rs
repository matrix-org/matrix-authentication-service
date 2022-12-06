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

use chrono::{DateTime, Duration, Utc};
use rand::{Rng, SeedableRng};
use serde::Serialize;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: Ulid,
    pub username: String,
    pub sub: String,
    pub primary_email: Option<UserEmail>,
}

impl User {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        vec![User {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            username: "john".to_owned(),
            sub: "123-456".to_owned(),
            primary_email: None,
        }]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Authentication {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserSession {
    pub id: Ulid,
    pub user: User,
    pub created_at: DateTime<Utc>,
    pub last_authentication: Option<Authentication>,
}

impl BrowserSession {
    #[must_use]
    pub fn was_authenticated_after(&self, after: DateTime<Utc>) -> bool {
        if let Some(auth) = &self.last_authentication {
            auth.created_at > after
        } else {
            false
        }
    }
}

impl BrowserSession {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        User::samples(now, rng)
            .into_iter()
            .map(|user| BrowserSession {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                user,
                created_at: now,
                last_authentication: None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmail {
    pub id: Ulid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

impl UserEmail {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        vec![
            Self {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                email: "alice@example.com".to_owned(),
                created_at: now,
                confirmed_at: Some(now),
            },
            Self {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                email: "bob@example.com".to_owned(),
                created_at: now,
                confirmed_at: None,
            },
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UserEmailVerificationState {
    AlreadyUsed { when: DateTime<Utc> },
    Expired { when: DateTime<Utc> },
    Valid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmailVerification {
    pub id: Ulid,
    pub email: UserEmail,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub state: UserEmailVerificationState,
}

impl UserEmailVerification {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        let states = [
            UserEmailVerificationState::AlreadyUsed {
                when: now - Duration::minutes(5),
            },
            UserEmailVerificationState::Expired {
                when: now - Duration::hours(5),
            },
            UserEmailVerificationState::Valid,
        ];

        states
            .into_iter()
            .flat_map(move |state| {
                let mut rng =
                    rand_chacha::ChaChaRng::from_rng(&mut *rng).expect("could not seed rng");
                UserEmail::samples(now, &mut rng)
                    .into_iter()
                    .map(move |email| Self {
                        id: Ulid::from_datetime_with_source(now.into(), &mut rng),
                        code: "123456".to_owned(),
                        email,
                        created_at: now - Duration::minutes(10),
                        state: state.clone(),
                    })
            })
            .collect()
    }
}
