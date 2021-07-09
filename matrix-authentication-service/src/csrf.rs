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

use csrf::CsrfProtection;
use data_encoding::BASE64;
use serde::Deserialize;

use crate::state::State;

/// A CSRF-protected form
#[derive(Deserialize)]
pub struct CsrfForm<T> {
    csrf: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> CsrfForm<T> {
    pub fn verify_csrf(self, request: &tide::Request<State>) -> tide::Result<T> {
        // Verify CSRF from request
        let csrf_config = &request.state().config().csrf;

        let cookie = request
            .cookie(csrf_config.cookie_name())
            .ok_or_else(|| anyhow::anyhow!("missing csrf cookie"))?; // TODO: proper error

        let protection = csrf_config.clone().into_protection();
        let cookie = BASE64.decode(cookie.value().as_bytes())?;
        let cookie = protection.parse_cookie(&cookie)?;

        let token = BASE64.decode(self.csrf.as_bytes())?;
        let token = protection.parse_token(&token)?;

        if protection.verify_token_pair(&token, &cookie) {
            Ok(self.inner)
        } else {
            Err(tide::Error::from_str(400, "failed CSRF validation"))
        }
    }
}
