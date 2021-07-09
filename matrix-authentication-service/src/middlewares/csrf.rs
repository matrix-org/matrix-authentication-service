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

use std::{convert::TryInto, time::Duration};

use async_trait::async_trait;
use csrf::CsrfProtection;
use data_encoding::BASE64;
use tide::http::Cookie;

#[derive(Debug, Clone)]
pub struct Middleware<T> {
    protection: T,
    ttl: Duration,
    cookie_name: String,
}

impl<T: CsrfProtection> Middleware<T> {
    pub fn new<D: Into<Duration>>(protection: T, cookie_name: String, ttl: D) -> Self {
        Self {
            protection,
            ttl: ttl.into(),
            cookie_name,
        }
    }
}

#[async_trait]
impl<Protection, State> tide::Middleware<State> for Middleware<Protection>
where
    Protection: CsrfProtection + 'static,
    State: Clone + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let previous_token_value = request
            .cookie(&self.cookie_name)
            .and_then(|cookie| BASE64.decode(cookie.value().as_bytes()).ok())
            .and_then(|decoded| self.protection.parse_cookie(&decoded).ok())
            .and_then(|parsed| parsed.value().try_into().ok());

        let (token, cookie) = self.protection.generate_token_pair(
            previous_token_value.as_ref(),
            self.ttl.as_secs().try_into()?,
        )?;

        request.set_ext(token);

        let mut response = next.run(request).await;
        response.insert_cookie(
            Cookie::build(self.cookie_name.clone(), cookie.b64_string())
                .http_only(true)
                .max_age(self.ttl.try_into()?)
                .same_site(tide::http::cookies::SameSite::Strict)
                .finish(),
        );

        Ok(response)
    }
}
