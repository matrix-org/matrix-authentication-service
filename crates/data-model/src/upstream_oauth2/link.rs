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

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthLink {
    pub id: Ulid,
    pub provider_id: Ulid,
    pub user_id: Option<Ulid>,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}
