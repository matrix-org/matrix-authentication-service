// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::net::IpAddr;

use mas_data_model::{BrowserSession, CompatSession, Session};
use mas_storage::Clock;

use crate::activity_tracker::ActivityTracker;

/// An activity tracker with an IP address bound to it.
#[derive(Clone)]
pub struct Bound {
    tracker: ActivityTracker,
    ip: Option<IpAddr>,
}

impl Bound {
    /// Create a new bound activity tracker.
    #[must_use]
    pub fn new(tracker: ActivityTracker, ip: Option<IpAddr>) -> Self {
        Self { tracker, ip }
    }

    /// Get the IP address bound to this activity tracker.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// Record activity in an OAuth 2.0 session.
    pub async fn record_oauth2_session(&self, clock: &dyn Clock, session: &Session) {
        self.tracker
            .record_oauth2_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a compatibility session.
    pub async fn record_compat_session(&self, clock: &dyn Clock, session: &CompatSession) {
        self.tracker
            .record_compat_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a browser session.
    pub async fn record_browser_session(&self, clock: &dyn Clock, session: &BrowserSession) {
        self.tracker
            .record_browser_session(clock, session, self.ip)
            .await;
    }
}
