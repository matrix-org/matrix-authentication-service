// Copyright 2022 Kévin Commaille.
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

//! An [OpenID Connect] client library for the [Matrix] specification.
//!
//! This is part of the [Matrix Authentication Service] project.
//!
//! # Scope
//!
//! The scope of this crate is to support OIDC features required by the
//! Matrix specification according to [MSC3861] and its sub-proposals.
//!
//! As such, it is compatible with the OpenID Connect 1.0 specification, but
//! also enforces Matrix-specific requirements or adds compatibility with new
//! [OAuth 2.0] features.
//!
//! # OpenID Connect and OAuth 2.0 Features
//!
//! - Grant Types:
//!   - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
//!   - [Client Credentials](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
//!   - [Device Code](https://www.rfc-editor.org/rfc/rfc8628) (TBD)
//! - [User Info](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
//! - Token:
//!   - [Refresh Token](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens)
//!   - [Introspection](https://www.rfc-editor.org/rfc/rfc7662)
//!   - [Revocation](https://www.rfc-editor.org/rfc/rfc7009)
//! - [Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
//! - [PKCE](https://www.rfc-editor.org/rfc/rfc7636)
//! - [Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
//!
//! # Matrix features
//!
//! - Client registration
//! - Login
//! - Matrix API Scopes
//! - Logout
//!
//! [OpenID Connect]: https://openid.net/connect/
//! [Matrix]: https://matrix.org/
//! [Matrix Authentication Service]: https://github.com/matrix-org/matrix-authentication-service
//! [MSC3861]: https://github.com/matrix-org/matrix-spec-proposals/pull/3861
//! [OAuth 2.0]: https://oauth.net/2/

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions, clippy::implicit_hasher)]

pub mod error;
pub mod http_service;
pub mod requests;
pub mod types;
mod utils;

use std::fmt;

#[doc(inline)]
pub use mas_jose as jose;

// Wrapper around `String` that cannot be used in a meaningful way outside of
// this crate. Used for string enums that only allow certain characters because
// their variant can't be private.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivString(String);

impl fmt::Debug for PrivString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
