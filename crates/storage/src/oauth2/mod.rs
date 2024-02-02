// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

//! Repositories to interact with entities related to the OAuth 2.0 protocol

mod access_token;
mod authorization_grant;
mod client;
mod device_code_grant;
mod refresh_token;
mod session;

pub use self::{
    access_token::OAuth2AccessTokenRepository,
    authorization_grant::OAuth2AuthorizationGrantRepository,
    client::OAuth2ClientRepository,
    device_code_grant::{OAuth2DeviceCodeGrantParams, OAuth2DeviceCodeGrantRepository},
    refresh_token::OAuth2RefreshTokenRepository,
    session::{OAuth2SessionFilter, OAuth2SessionRepository},
};
