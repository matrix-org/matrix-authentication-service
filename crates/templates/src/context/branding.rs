// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use std::sync::Arc;

use minijinja::{
    value::{Enumerator, Object},
    Value,
};

/// Site branding information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBranding {
    server_name: Arc<str>,
    policy_uri: Option<Arc<str>>,
    tos_uri: Option<Arc<str>>,
    imprint: Option<Arc<str>>,
}

impl SiteBranding {
    /// Create a new site branding based on the given server name.
    #[must_use]
    pub fn new(server_name: impl Into<Arc<str>>) -> Self {
        Self {
            server_name: server_name.into(),
            policy_uri: None,
            tos_uri: None,
            imprint: None,
        }
    }

    /// Set the policy URI.
    #[must_use]
    pub fn with_policy_uri(mut self, policy_uri: impl Into<Arc<str>>) -> Self {
        self.policy_uri = Some(policy_uri.into());
        self
    }

    /// Set the terms of service URI.
    #[must_use]
    pub fn with_tos_uri(mut self, tos_uri: impl Into<Arc<str>>) -> Self {
        self.tos_uri = Some(tos_uri.into());
        self
    }

    /// Set the imprint.
    #[must_use]
    pub fn with_imprint(mut self, imprint: impl Into<Arc<str>>) -> Self {
        self.imprint = Some(imprint.into());
        self
    }
}

impl Object for SiteBranding {
    fn get_value(self: &Arc<Self>, name: &Value) -> Option<Value> {
        match name.as_str()? {
            "server_name" => Some(self.server_name.clone().into()),
            "policy_uri" => self.policy_uri.clone().map(Value::from),
            "tos_uri" => self.tos_uri.clone().map(Value::from),
            "imprint" => self.imprint.clone().map(Value::from),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&["server_name", "policy_uri", "tos_uri", "imprint"])
    }
}
