// Copyright 2021-2022 The Matrix.org Foundation C.I.C.
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

use mas_config::{CookiesConfig, CsrfConfig, HttpConfig};
use mas_email::Mailer;
use mas_templates::Templates;
use sqlx::PgPool;
use warp::{filters::BoxedFilter, Filter, Reply};

mod account;
mod index;
mod login;
mod logout;
mod reauth;
mod register;
mod shared;
mod verify;

use self::{
    account::filter as account, index::filter as index, login::filter as login,
    logout::filter as logout, reauth::filter as reauth, register::filter as register,
    verify::filter as verify,
};
pub(crate) use self::{
    login::LoginRequest, reauth::ReauthRequest, register::RegisterRequest, shared::PostAuthAction,
};

pub(super) fn filter(
    pool: &PgPool,
    templates: &Templates,
    mailer: &Mailer,
    http_config: &HttpConfig,
    csrf_config: &CsrfConfig,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(Box<dyn Reply>,)> {
    let index = index(pool, templates, http_config, csrf_config, cookies_config);
    let account = account(
        pool,
        templates,
        mailer,
        http_config,
        csrf_config,
        cookies_config,
    );
    let login = login(pool, templates, csrf_config, cookies_config);
    let register = register(pool, templates, csrf_config, cookies_config);
    let logout = logout(pool, cookies_config);
    let reauth = reauth(pool, templates, csrf_config, cookies_config);
    let verify = verify(pool, templates, csrf_config, cookies_config);

    index
        .or(account)
        .unify()
        .or(login)
        .unify()
        .or(register)
        .unify()
        .or(logout)
        .unify()
        .or(reauth)
        .unify()
        .or(verify)
        .unify()
        .boxed()
}
