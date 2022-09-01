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

use signature::Signature as _;

#[derive(Debug)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl Signature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn from_signature<S>(signature: &S) -> Self
    where
        S: signature::Signature,
    {
        Self {
            bytes: signature.as_bytes().to_vec(),
        }
    }

    pub fn to_signature<S>(&self) -> Result<S, signature::Error>
    where
        S: signature::Signature,
    {
        S::from_bytes(self.as_bytes())
    }
}
