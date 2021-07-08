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

use std::convert::TryInto;
use std::future::Future;
use std::pin::Pin;

use csrf::CsrfProtection;
use data_encoding::BASE64;
use tide::http::Cookie;
use time::Duration;

use crate::state::State;

pub fn middleware<'a>(
    mut request: tide::Request<State>,
    next: tide::Next<'a, State>,
) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
    Box::pin(async {
        // Generate, inject and save cookie with CSRF
        let state = request.state();
        let protection = state.csrf_protection();
        let previous_token_value = request
            .cookie("csrf")
            .and_then(|cookie| BASE64.decode(cookie.value().as_bytes()).ok())
            .and_then(|decoded| protection.parse_cookie(&decoded).ok())
            .and_then(|parsed| parsed.value().try_into().ok());
        let (token, cookie) =
            protection.generate_token_pair(previous_token_value.as_ref(), 3600)?;

        request.set_ext(token);

        let mut response = next.run(request).await;
        response.insert_cookie(
            Cookie::build("csrf", cookie.b64_string())
                .http_only(true)
                .max_age(Duration::seconds(3600))
                .same_site(tide::http::cookies::SameSite::Strict)
                .finish(),
        );

        Ok(response)
    })
}
