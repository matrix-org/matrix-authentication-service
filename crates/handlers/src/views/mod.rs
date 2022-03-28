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

pub mod account;
pub mod index;
pub mod login;
pub mod logout;
pub mod reauth;
pub mod register;
pub mod shared;
pub mod verify;

pub(crate) use self::{
    login::LoginRequest, reauth::ReauthRequest, register::RegisterRequest, shared::PostAuthAction,
};
