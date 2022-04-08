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

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct WebFingerResponse {
    subject: String,
    links: Vec<WebFingerLink>,
}

impl WebFingerResponse {
    #[must_use]
    pub const fn new(subject: String) -> Self {
        Self {
            subject,
            links: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_link(mut self, link: WebFingerLink) -> Self {
        self.links.push(link);
        self
    }

    #[must_use]
    pub fn with_issuer(self, issuer: Url) -> Self {
        self.with_link(WebFingerLink::issuer(issuer))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "rel")]
pub enum WebFingerLink {
    #[serde(rename = "http://openid.net/specs/connect/1.0/issuer")]
    OidcIssuer { href: Url },
}

impl WebFingerLink {
    #[must_use]
    pub const fn issuer(href: Url) -> Self {
        Self::OidcIssuer { href }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serialize_webfinger_response_test() {
        let res = WebFingerResponse::new("acct:john@example.com".to_string())
            .with_issuer(Url::parse("https://account.example.com/").unwrap());

        let res = serde_json::to_value(&res).unwrap();

        assert_eq!(
            res,
            json!({
                "subject": "acct:john@example.com",
                "links": [{
                    "rel": "http://openid.net/specs/connect/1.0/issuer",
                    "href": "https://account.example.com/",
                }]
            })
        );
    }
}
