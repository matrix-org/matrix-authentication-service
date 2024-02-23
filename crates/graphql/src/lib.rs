// Copyright 2022-2023 The Matrix.org Foundation C.I.C.
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

#![deny(clippy::future_not_send)]
#![allow(clippy::module_name_repetitions, clippy::unused_async)]

use async_graphql::EmptySubscription;
use mas_data_model::{BrowserSession, Session, User};
use ulid::Ulid;

mod model;
mod mutations;
mod query;
mod state;

pub use self::{
    model::{CreationEvent, Node},
    mutations::Mutation,
    query::Query,
    state::{BoxState, State},
};

pub type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<Query, Mutation, EmptySubscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(Query::new(), Mutation::new(), EmptySubscription)
        .register_output_type::<Node>()
        .register_output_type::<CreationEvent>()
}

/// The identity of the requester.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Requester {
    /// The requester presented no authentication information.
    #[default]
    Anonymous,

    /// The requester is a browser session, stored in a cookie.
    BrowserSession(Box<BrowserSession>),

    /// The requester is a OAuth2 session, with an access token.
    OAuth2Session(Box<(Session, Option<User>)>),
}

trait OwnerId {
    fn owner_id(&self) -> Option<Ulid>;
}

impl OwnerId for User {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.id)
    }
}

impl OwnerId for BrowserSession {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.user.id)
    }
}

impl OwnerId for mas_data_model::UserEmail {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.user_id)
    }
}

impl OwnerId for Session {
    fn owner_id(&self) -> Option<Ulid> {
        self.user_id
    }
}

impl OwnerId for mas_data_model::CompatSession {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.user_id)
    }
}

impl OwnerId for mas_data_model::UpstreamOAuthLink {
    fn owner_id(&self) -> Option<Ulid> {
        self.user_id
    }
}

/// A dumb wrapper around a `Ulid` to implement `OwnerId` for it.
pub struct UserId(Ulid);

impl OwnerId for UserId {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.0)
    }
}

impl Requester {
    fn browser_session(&self) -> Option<&BrowserSession> {
        match self {
            Self::BrowserSession(session) => Some(session),
            Self::OAuth2Session(_) | Self::Anonymous => None,
        }
    }

    fn user(&self) -> Option<&User> {
        match self {
            Self::BrowserSession(session) => Some(&session.user),
            Self::OAuth2Session(tuple) => tuple.1.as_ref(),
            Self::Anonymous => None,
        }
    }

    fn oauth2_session(&self) -> Option<&Session> {
        match self {
            Self::OAuth2Session(tuple) => Some(&tuple.0),
            Self::BrowserSession(_) | Self::Anonymous => None,
        }
    }

    /// Returns true if the requester can access the resource.
    fn is_owner_or_admin(&self, resource: &impl OwnerId) -> bool {
        // If the requester is an admin, they can do anything.
        if self.is_admin() {
            return true;
        }

        // Otherwise, they must be the owner of the resource.
        let Some(owner_id) = resource.owner_id() else {
            return false;
        };

        let Some(user) = self.user() else {
            return false;
        };

        user.id == owner_id
    }

    fn is_admin(&self) -> bool {
        match self {
            Self::OAuth2Session(tuple) => {
                // TODO: is this the right scope?
                // This has to be in sync with the policy
                tuple.0.scope.contains("urn:mas:admin")
            }
            Self::BrowserSession(_) | Self::Anonymous => false,
        }
    }
}

impl From<BrowserSession> for Requester {
    fn from(session: BrowserSession) -> Self {
        Self::BrowserSession(Box::new(session))
    }
}

impl<T> From<Option<T>> for Requester
where
    T: Into<Requester>,
{
    fn from(session: Option<T>) -> Self {
        session.map(Into::into).unwrap_or_default()
    }
}
