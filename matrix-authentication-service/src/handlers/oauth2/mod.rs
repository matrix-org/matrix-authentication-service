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
    config::{CookiesConfig, OAuth2Config},
    templates::Templates,
};

mod authorization;
mod discovery;
mod introspection;
mod token;

use self::{
    authorization::filter as authorization, discovery::filter as discovery,
    introspection::filter as introspection, token::filter as token,
};

pub fn filter(
    pool: &PgPool,
    templates: &Templates,
    oauth2_config: &OAuth2Config,
    cookies_config: &CookiesConfig,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static {
    discovery(oauth2_config)
        .or(authorization(
            pool,
            templates,
            oauth2_config,
            cookies_config,
        ))
        .or(introspection(pool, oauth2_config))
        .or(token(pool, oauth2_config))
}
