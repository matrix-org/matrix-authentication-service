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

use std::{collections::HashSet, future::Future};

use async_trait::async_trait;
use mas_iana::jose::JsonWebSignatureAlg;

use crate::JsonWebSignatureHeader;

#[async_trait]
pub trait SigningKeystore {
    fn supported_algorithms(&self) -> HashSet<JsonWebSignatureAlg>;

    async fn prepare_header(
        &self,
        alg: JsonWebSignatureAlg,
    ) -> anyhow::Result<JsonWebSignatureHeader>;

    async fn sign(&self, header: &JsonWebSignatureHeader, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub trait VerifyingKeystore {
    type Error;
    type Future: Future<Output = Result<(), Self::Error>>;

    fn verify(&self, header: &JsonWebSignatureHeader, msg: &[u8], signature: &[u8])
        -> Self::Future;
}
