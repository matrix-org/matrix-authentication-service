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

use sqlx::PgPool;
use warp::{Filter, Rejection, Reply};

use crate::{
    config::{CookiesConfig, CsrfConfig},
    templates::Templates,
};

mod index;
mod login;
mod logout;
mod reauth;
mod register;

pub use self::login::LoginRequest;
use self::{
    index::filter as index, login::filter as login, logout::filter as logout,
    reauth::filter as reauth, register::filter as register,
};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    index(pool, templates, csrf_config, cookies_config)
        .or(login(pool, templates, csrf_config, cookies_config))
        .or(register(pool, templates, csrf_config, cookies_config))
        .or(logout(pool, cookies_config))
        .or(reauth(pool, templates, csrf_config, cookies_config))
        .boxed()
}
