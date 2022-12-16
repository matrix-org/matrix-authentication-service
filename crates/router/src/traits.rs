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

use std::borrow::{Borrow, Cow};

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

    fn relative_url(&self) -> Cow<'static, str> {
        let path = self.path();
        if let Some(query) = self.query() {
            let query = serde_urlencoded::to_string(query).unwrap();
            format!("{path}?{query}").into()
        } else {
            path
        }
    }

    fn absolute_url(&self, base: &Url) -> Url {
        let relative = self.relative_url();
        base.join(relative.borrow()).unwrap()
    }

    fn go(&self) -> axum::response::Redirect {
        axum::response::Redirect::to(&self.relative_url())
    }

    fn go_absolute(&self, base: &Url) -> axum::response::Redirect {
        axum::response::Redirect::to(self.absolute_url(base).as_str())
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
