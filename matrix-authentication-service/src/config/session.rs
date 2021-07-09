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
use serde_with::serde_as;
use tide::{
    sessions::{SessionMiddleware, SessionStore},
    Middleware,
};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde_as(as = "serde_with::hex::Hex")]
    secret: Vec<u8>,
}

impl Config {
    pub fn to_middleware<State: Clone + Send + Sync + 'static>(
        &self,
        store: impl SessionStore,
    ) -> impl Middleware<State> {
        SessionMiddleware::new(store, &self.secret)
    }
}
