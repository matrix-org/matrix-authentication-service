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

use std::collections::HashSet;

use async_trait::async_trait;

use crate::{iana::JsonWebSignatureAlgorithm, JsonWebKeySet, JwtHeader};

#[async_trait]
pub trait SigningKeystore {
    fn supported_algorithms(self) -> HashSet<JsonWebSignatureAlgorithm>;

    async fn prepare_header(self, alg: JsonWebSignatureAlgorithm) -> anyhow::Result<JwtHeader>;

    async fn sign(self, header: &JwtHeader, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
pub trait VerifyingKeystore {
    async fn verify(self, header: &JwtHeader, msg: &[u8], signature: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
pub trait ExportJwks {
    async fn export_jwks(&self) -> anyhow::Result<JsonWebKeySet>;
}
