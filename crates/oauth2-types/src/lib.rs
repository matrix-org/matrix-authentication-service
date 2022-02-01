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

#![forbid(unsafe_code)]
#![deny(clippy::all, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]

use mas_iana::oauth::OAuthAuthorizationEndpointResponseType;

pub trait ResponseTypeExt {
    fn has_code(&self) -> bool;
    fn has_token(&self) -> bool;
    fn has_id_token(&self) -> bool;
}

impl ResponseTypeExt for OAuthAuthorizationEndpointResponseType {
    fn has_code(&self) -> bool {
        matches!(
            self,
            Self::Code | Self::CodeToken | Self::CodeIdToken | Self::CodeIdTokenToken
        )
    }

    fn has_token(&self) -> bool {
        matches!(
            self,
            Self::Token | Self::CodeToken | Self::IdTokenToken | Self::CodeIdTokenToken
        )
    }

    fn has_id_token(&self) -> bool {
        matches!(
            self,
            Self::IdToken | Self::IdTokenToken | Self::CodeIdToken | Self::CodeIdTokenToken
        )
    }
}

pub mod errors;
pub mod oidc;
pub mod pkce;
pub mod requests;
pub mod scope;

pub mod prelude {
    pub use crate::{pkce::CodeChallengeMethodExt, ResponseTypeExt};
}

#[cfg(test)]
mod test_utils;
