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

use async_graphql::{Enum, Interface, Object, SimpleObject};
use chrono::{DateTime, Utc};

mod browser_sessions;
mod compat_sessions;
mod cursor;
mod matrix;
mod node;
mod oauth;
mod site_config;
mod upstream_oauth;
mod users;
mod viewer;

pub use self::{
    browser_sessions::{Authentication, BrowserSession},
    compat_sessions::{CompatSession, CompatSsoLogin},
    cursor::{Cursor, NodeCursor},
    node::{Node, NodeType},
    oauth::{OAuth2Client, OAuth2Session},
    site_config::{SiteConfig, SITE_CONFIG_ID},
    upstream_oauth::{UpstreamOAuth2Link, UpstreamOAuth2Provider},
    users::{AppSession, User, UserEmail},
    viewer::{Anonymous, Viewer, ViewerSession},
};

/// An object with a creation date.
#[derive(Interface)]
#[graphql(field(
    name = "created_at",
    desc = "When the object was created.",
    ty = "DateTime<Utc>"
))]
pub enum CreationEvent {
    Authentication(Box<Authentication>),
    CompatSession(Box<CompatSession>),
    BrowserSession(Box<BrowserSession>),
    UserEmail(Box<UserEmail>),
    UpstreamOAuth2Provider(Box<UpstreamOAuth2Provider>),
    UpstreamOAuth2Link(Box<UpstreamOAuth2Link>),
    OAuth2Session(Box<OAuth2Session>),
}

pub struct PreloadedTotalCount(pub Option<usize>);

#[Object]
impl PreloadedTotalCount {
    /// Identifies the total count of items in the connection.
    async fn total_count(&self) -> Result<usize, async_graphql::Error> {
        self.0
            .ok_or_else(|| async_graphql::Error::new("total count not preloaded"))
    }
}

/// The state of a session
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum SessionState {
    /// The session is active.
    Active,

    /// The session is no longer active.
    Finished,
}

/// The type of a user agent
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum DeviceType {
    /// A personal computer, laptop or desktop
    Pc,

    /// A mobile phone. Can also sometimes be a tablet.
    Mobile,

    /// A tablet
    Tablet,

    /// Unknown device type
    Unknown,
}

impl From<mas_data_model::DeviceType> for DeviceType {
    fn from(device_type: mas_data_model::DeviceType) -> Self {
        match device_type {
            mas_data_model::DeviceType::Pc => Self::Pc,
            mas_data_model::DeviceType::Mobile => Self::Mobile,
            mas_data_model::DeviceType::Tablet => Self::Tablet,
            mas_data_model::DeviceType::Unknown => Self::Unknown,
        }
    }
}

/// A parsed user agent string
#[derive(SimpleObject)]
pub struct UserAgent {
    /// The user agent string
    pub raw: String,

    /// The name of the browser
    pub name: Option<String>,

    /// The version of the browser
    pub version: Option<String>,

    /// The operating system name
    pub os: Option<String>,

    /// The operating system version
    pub os_version: Option<String>,

    /// The device model
    pub model: Option<String>,

    /// The device type
    pub device_type: DeviceType,
}

impl From<mas_data_model::UserAgent> for UserAgent {
    fn from(ua: mas_data_model::UserAgent) -> Self {
        Self {
            raw: ua.raw,
            name: ua.name,
            version: ua.version,
            os: ua.os,
            os_version: ua.os_version,
            model: ua.model,
            device_type: ua.device_type.into(),
        }
    }
}
