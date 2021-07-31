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
use warp::{filters::BoxedFilter, Filter, Reply};

use crate::config::{CookiesConfig, OAuth2Config};

mod authorization;
mod discovery;

use self::{authorization::filter as authorization, discovery::filter as discovery};

pub fn filter(
    pool: &PgPool,
    oauth2_config: &OAuth2Config,
    cookies_config: &CookiesConfig,
) -> BoxedFilter<(impl Reply,)> {
    discovery(oauth2_config)
        .or(authorization(pool, oauth2_config, cookies_config))
        .boxed()
}
