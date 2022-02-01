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

use std::sync::Arc;

use hyper::Method;
use mas_config::{CookiesConfig, HttpConfig, OAuth2Config};
use mas_jose::StaticKeystore;
use mas_templates::Templates;
use mas_warp_utils::filters::cors::cors;
use sqlx::PgPool;
use warp::{filters::BoxedFilter, Filter, Reply};

mod authorization;
mod discovery;
mod introspection;
mod keys;
mod token;
mod userinfo;

pub(crate) use self::authorization::ContinueAuthorizationGrant;
use self::{
    authorization::filter as authorization, discovery::filter as discovery,
    introspection::filter as introspection, keys::filter as keys, token::filter as token,
    userinfo::filter as userinfo,
};

pub fn filter(
    pool: &PgPool,
    templates: &Templates,
    key_store: &Arc<StaticKeystore>,
    oauth2_config: &OAuth2Config,
    http_config: &HttpConfig,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(impl Reply,)> {
    let discovery = discovery(key_store.as_ref(), http_config);
    let keys = keys(key_store);
    let authorization = authorization(pool, templates, oauth2_config, cookies_config);
    let userinfo = userinfo(pool, oauth2_config);
    let introspection = introspection(pool, oauth2_config, http_config);
    let token = token(pool, key_store, oauth2_config, http_config);

    let filter = discovery
        .or(keys)
        .unify()
        .or(userinfo)
        .unify()
        .or(token)
        .unify()
        .or(introspection)
        .unify()
        .with(cors().allow_methods([Method::POST, Method::GET]));

    filter.or(authorization).boxed()
}
