// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::borrow::Cow;

use serde::Serialize;
use url::Url;

pub trait Route {
    type Query: Serialize;
    fn route() -> &'static str;
    fn query(&self) -> Option<&Self::Query> {
        None
    }

    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed(Self::route())
    }

    fn path_and_query(&self) -> Cow<'static, str> {
        let path = self.path();
        if let Some(query) = self.query() {
            let query = serde_urlencoded::to_string(query).unwrap();

            if query.is_empty() {
                path
            } else {
                format!("{path}?{query}").into()
            }
        } else {
            path
        }
    }

    fn absolute_url(&self, base: &Url) -> Url {
        let relative = self.path_and_query();
        let relative = relative.trim_start_matches('/');
        base.join(relative).unwrap()
    }
}

pub trait SimpleRoute {
    const PATH: &'static str;
}

impl<T: SimpleRoute> Route for T {
    type Query = ();
    fn route() -> &'static str {
        Self::PATH
    }
}
