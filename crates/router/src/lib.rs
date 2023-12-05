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

pub(crate) mod endpoints;
pub(crate) mod traits;
mod url_builder;

pub use self::{endpoints::*, traits::Route, url_builder::UrlBuilder};

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ulid::Ulid;
    use url::Url;

    use super::*;

    #[test]
    fn test_relative_urls() {
        assert_eq!(
            OidcConfiguration.path_and_query(),
            Cow::Borrowed("/.well-known/openid-configuration")
        );
        assert_eq!(Index.path_and_query(), Cow::Borrowed("/"));
        assert_eq!(
            Login::and_continue_grant(Ulid::nil()).path_and_query(),
            Cow::Borrowed("/login?kind=continue_authorization_grant&id=00000000000000000000000000")
        );
    }

    #[test]
    fn test_absolute_urls() {
        let base = Url::try_from("https://example.com/").unwrap();
        assert_eq!(Index.absolute_url(&base).as_str(), "https://example.com/");
        assert_eq!(
            OidcConfiguration.absolute_url(&base).as_str(),
            "https://example.com/.well-known/openid-configuration"
        );
    }
}
