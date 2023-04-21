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

use async_graphql::Union;

use crate::model::{BrowserSession, User};

mod anonymous;
pub use self::anonymous::Anonymous;

/// Represents the current viewer
#[derive(Union)]
pub enum Viewer {
    User(User),
    Anonymous(Anonymous),
}

impl Viewer {
    pub fn user(user: mas_data_model::User) -> Self {
        Self::User(User(user))
    }

    pub fn anonymous() -> Self {
        Self::Anonymous(Anonymous)
    }
}

/// Represents the current viewer's session
#[derive(Union)]
pub enum ViewerSession {
    BrowserSession(BrowserSession),
    Anonymous(Anonymous),
}

impl ViewerSession {
    pub fn browser_session(session: mas_data_model::BrowserSession) -> Self {
        Self::BrowserSession(BrowserSession(session))
    }

    pub fn anonymous() -> Self {
        Self::Anonymous(Anonymous)
    }
}
