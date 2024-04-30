// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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

use async_graphql::{Interface, ID};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use super::{
    Anonymous, Authentication, BrowserSession, CompatSession, CompatSsoLogin, OAuth2Client,
    OAuth2Session, SiteConfig, UpstreamOAuth2Link, UpstreamOAuth2Provider, User, UserEmail,
};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeType {
    Authentication,
    BrowserSession,
    CompatSession,
    CompatSsoLogin,
    OAuth2Client,
    OAuth2Session,
    UpstreamOAuth2Provider,
    UpstreamOAuth2Link,
    User,
    UserEmail,
}

#[derive(Debug, Error)]
#[error("invalid id")]
pub enum InvalidID {
    InvalidFormat,
    InvalidUlid(#[from] ulid::DecodeError),
    UnknownPrefix,
    TypeMismatch { got: NodeType, expected: NodeType },
}

impl NodeType {
    fn to_prefix(self) -> &'static str {
        match self {
            NodeType::Authentication => "authentication",
            NodeType::BrowserSession => "browser_session",
            NodeType::CompatSession => "compat_session",
            NodeType::CompatSsoLogin => "compat_sso_login",
            NodeType::OAuth2Client => "oauth2_client",
            NodeType::OAuth2Session => "oauth2_session",
            NodeType::UpstreamOAuth2Provider => "upstream_oauth2_provider",
            NodeType::UpstreamOAuth2Link => "upstream_oauth2_link",
            NodeType::User => "user",
            NodeType::UserEmail => "user_email",
        }
    }

    fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "authentication" => Some(NodeType::Authentication),
            "browser_session" => Some(NodeType::BrowserSession),
            "compat_session" => Some(NodeType::CompatSession),
            "compat_sso_login" => Some(NodeType::CompatSsoLogin),
            "oauth2_client" => Some(NodeType::OAuth2Client),
            "oauth2_session" => Some(NodeType::OAuth2Session),
            "upstream_oauth2_provider" => Some(NodeType::UpstreamOAuth2Provider),
            "upstream_oauth2_link" => Some(NodeType::UpstreamOAuth2Link),
            "user" => Some(NodeType::User),
            "user_email" => Some(NodeType::UserEmail),
            _ => None,
        }
    }

    pub fn serialize(self, id: impl Into<Ulid>) -> String {
        let prefix = self.to_prefix();
        let id = id.into();
        format!("{prefix}:{id}")
    }

    pub fn id(self, id: impl Into<Ulid>) -> ID {
        ID(self.serialize(id))
    }

    pub fn deserialize(serialized: &str) -> Result<(Self, Ulid), InvalidID> {
        let (prefix, id) = serialized.split_once(':').ok_or(InvalidID::InvalidFormat)?;
        let prefix = NodeType::from_prefix(prefix).ok_or(InvalidID::UnknownPrefix)?;
        let id = id.parse()?;
        Ok((prefix, id))
    }

    pub fn from_id(id: &ID) -> Result<(Self, Ulid), InvalidID> {
        Self::deserialize(&id.0)
    }

    pub fn extract_ulid(self, id: &ID) -> Result<Ulid, InvalidID> {
        let (node_type, ulid) = Self::deserialize(&id.0)?;

        if node_type == self {
            Ok(ulid)
        } else {
            Err(InvalidID::TypeMismatch {
                got: node_type,
                expected: self,
            })
        }
    }
}

/// An object with an ID.
#[derive(Interface)]
#[graphql(field(name = "id", desc = "ID of the object.", ty = "ID"))]
pub enum Node {
    Anonymous(Box<Anonymous>),
    Authentication(Box<Authentication>),
    BrowserSession(Box<BrowserSession>),
    CompatSession(Box<CompatSession>),
    CompatSsoLogin(Box<CompatSsoLogin>),
    OAuth2Client(Box<OAuth2Client>),
    OAuth2Session(Box<OAuth2Session>),
    SiteConfig(Box<SiteConfig>),
    UpstreamOAuth2Provider(Box<UpstreamOAuth2Provider>),
    UpstreamOAuth2Link(Box<UpstreamOAuth2Link>),
    User(Box<User>),
    UserEmail(Box<UserEmail>),
}
