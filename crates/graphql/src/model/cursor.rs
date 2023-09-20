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

use async_graphql::connection::OpaqueCursor;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub use super::NodeType;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCursor(pub NodeType, pub Ulid);

impl NodeCursor {
    pub fn extract_for_types(&self, node_types: &[NodeType]) -> Result<Ulid, async_graphql::Error> {
        if node_types.contains(&self.0) {
            Ok(self.1)
        } else {
            Err(async_graphql::Error::new("invalid cursor"))
        }
    }

    pub fn extract_for_type(&self, node_type: NodeType) -> Result<Ulid, async_graphql::Error> {
        if self.0 == node_type {
            Ok(self.1)
        } else {
            Err(async_graphql::Error::new("invalid cursor"))
        }
    }
}

pub type Cursor = OpaqueCursor<NodeCursor>;
