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

use serde::Deserialize;

use crate::middlewares::CsrfToken;

/// A CSRF-protected form
#[derive(Deserialize)]
pub struct CsrfForm<T> {
    csrf: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> CsrfForm<T> {
    pub fn verify_csrf<State>(self, request: &tide::Request<State>) -> tide::Result<T>
    where
        State: Clone + Send + Sync + 'static,
    {
        // Verify CSRF from request
        let csrf_token: &CsrfToken = request
            .ext()
            .ok_or_else(|| anyhow::anyhow!("missing csrf cookie"))?; // TODO: proper error

        csrf_token.verify_form_value(&self.csrf)?;
        Ok(self.inner)
    }
}
