// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use serde::Serialize;

use crate::traits::{StorageBackend, StorageBackendMarker};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(bound = "T: StorageBackend")]
pub struct Client<T: StorageBackend> {
    #[serde(skip_serializing)]
    pub data: T::ClientData,
    pub client_id: String,
}

impl<S: StorageBackendMarker> From<Client<S>> for Client<()> {
    fn from(c: Client<S>) -> Self {
        Client {
            data: (),
            client_id: c.client_id,
        }
    }
}
