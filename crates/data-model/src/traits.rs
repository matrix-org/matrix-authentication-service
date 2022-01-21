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

pub trait StorageBackend {
    type UserData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type UserEmailData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type UserEmailVerificationData: Clone
        + Debug
        + PartialEq
        + Serialize
        + DeserializeOwned
        + Default;
    type AuthenticationData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type BrowserSessionData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type ClientData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type SessionData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type AuthorizationGrantData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type AccessTokenData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
    type RefreshTokenData: Clone + Debug + PartialEq + Serialize + DeserializeOwned + Default;
}

impl StorageBackend for () {
    type AccessTokenData = ();
    type AuthenticationData = ();
    type AuthorizationGrantData = ();
    type BrowserSessionData = ();
    type ClientData = ();
    type RefreshTokenData = ();
    type SessionData = ();
    type UserData = ();
    type UserEmailData = ();
    type UserEmailVerificationData = ();
}
