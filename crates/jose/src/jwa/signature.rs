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

use signature::SignatureEncoding as _;

#[derive(Debug, Clone)]
pub struct Signature {
    bytes: Box<[u8]>,
}

impl From<Signature> for Box<[u8]> {
    fn from(val: Signature) -> Self {
        val.bytes
    }
}

impl<'a> From<&'a [u8]> for Signature {
    fn from(value: &'a [u8]) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}

impl signature::SignatureEncoding for Signature {
    type Repr = Box<[u8]>;
}

impl Signature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub fn from_signature<S>(signature: &S) -> Self
    where
        S: signature::SignatureEncoding,
    {
        Self {
            bytes: signature.to_vec().into(),
        }
    }

    pub fn to_signature<S>(&self) -> Result<S, signature::Error>
    where
        S: signature::SignatureEncoding,
    {
        S::try_from(&self.to_bytes()).map_err(|_| signature::Error::default())
    }
}
