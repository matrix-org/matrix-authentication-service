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

pub trait StorageBackendMarker: StorageBackend {}

pub trait StorageBackend {
    type UserData: Clone + std::fmt::Debug + PartialEq;
    type AuthenticationData: Clone + std::fmt::Debug + PartialEq;
    type BrowserSessionData: Clone + std::fmt::Debug + PartialEq;
    type ClientData: Clone + std::fmt::Debug + PartialEq;
    type SessionData: Clone + std::fmt::Debug + PartialEq;
    type AuthorizationGrantData: Clone + std::fmt::Debug + PartialEq;
    type AccessTokenData: Clone + std::fmt::Debug + PartialEq;
    type RefreshTokenData: Clone + std::fmt::Debug + PartialEq;
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
}
