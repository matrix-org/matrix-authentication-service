// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

//! [OAuth 2.0] and [OpenID Connect] types.
//!
//! This is part of the [Matrix Authentication Service] project.
//!
//! [OAuth 2.0]: https://oauth.net/2/
//! [OpenID Connect]: https://openid.net/connect/
//! [Matrix Authentication Service]: https://github.com/matrix-org/matrix-authentication-service

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub mod errors;
pub mod oidc;
pub mod pkce;
pub mod registration;
pub mod requests;
pub mod response_type;
pub mod scope;
pub mod webfinger;

/// Traits intended for blanket imports.
pub mod prelude {
    pub use crate::pkce::CodeChallengeMethodExt;
}

#[cfg(test)]
mod test_utils;
