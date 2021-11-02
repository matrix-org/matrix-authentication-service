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

use oauth2_types::scope::Scope;
use serde::Serialize;

use super::client::Client;
use crate::{
    traits::{StorageBackend, StorageBackendMarker},
    users::BrowserSession,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct Session<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::SessionData,
    pub browser_session: BrowserSession<T>,
    pub client: Client<T>,
    pub scope: Scope,
}

impl<S: StorageBackendMarker> From<Session<S>> for Session<()> {
    fn from(s: Session<S>) -> Self {
        Session {
            data: (),
            browser_session: s.browser_session.into(),
            client: s.client.into(),
            scope: s.scope,
        }
    }
}
