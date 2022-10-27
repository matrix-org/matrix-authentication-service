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

use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

pub trait StorageBackendMarker: StorageBackend {}

/// Marker trait of traits that should be implemented by primary keys
pub trait Data:
    Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default + Sync + Send
{
}

impl<T: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default + Sync + Send> Data
    for T
{
}

pub trait StorageBackend {
    type UserData: Data;
    type UserEmailData: Data;
    type UserEmailVerificationData: Data;
    type AuthenticationData: Data;
    type BrowserSessionData: Data;
    type ClientData: Data;
    type SessionData: Data;
    type AuthorizationGrantData: Data;
    type AccessTokenData: Data;
    type RefreshTokenData: Data;
    type CompatAccessTokenData: Data;
    type CompatRefreshTokenData: Data;
    type CompatSessionData: Data;
    type CompatSsoLoginData: Data;
}

impl StorageBackend for () {
    type AccessTokenData = ();
    type AuthenticationData = ();
    type AuthorizationGrantData = ();
    type BrowserSessionData = ();
    type ClientData = ();
    type CompatAccessTokenData = ();
    type CompatRefreshTokenData = ();
    type CompatSessionData = ();
    type CompatSsoLoginData = ();
    type RefreshTokenData = ();
    type SessionData = ();
    type UserData = ();
    type UserEmailData = ();
    type UserEmailVerificationData = ();
}
