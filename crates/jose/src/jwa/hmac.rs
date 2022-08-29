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

use std::marker::PhantomData;

use digest::{
    crypto_common::BlockSizeUser,
    generic_array::{ArrayLength, GenericArray},
    Digest, Mac, OutputSizeUser,
};
use signature::{Signer, Verifier};
use thiserror::Error;

pub struct Signature<S: ArrayLength<u8>> {
    signature: GenericArray<u8, S>,
}

impl<S: ArrayLength<u8>> PartialEq for Signature<S> {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
    }
}

impl<S: ArrayLength<u8>> Eq for Signature<S> {}

impl<S: ArrayLength<u8>> std::fmt::Debug for Signature<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.signature)
    }
}

impl<S: ArrayLength<u8>> signature::Signature for Signature<S> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        if bytes.len() != S::to_usize() {
            return Err(signature::Error::new());
        }

        Ok(Self {
            signature: GenericArray::from_slice(bytes).clone(),
        })
    }
}

impl<S: ArrayLength<u8>> AsRef<[u8]> for Signature<S> {
    fn as_ref(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

pub struct Hmac<D> {
    key: Vec<u8>,
    digest: PhantomData<D>,
}

#[derive(Error, Debug)]
#[error("invalid length")]
pub struct InvalidLength;

impl<D> From<Vec<u8>> for Hmac<D> {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key,
            digest: PhantomData::default(),
        }
    }
}

impl<D: Digest + BlockSizeUser>
    Signer<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>> for Hmac<D>
{
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>, signature::Error>
    {
        let mut mac = <hmac::SimpleHmac<D> as Mac>::new_from_slice(&self.key)
            .map_err(signature::Error::from_source)?;
        mac.update(msg);
        let signature = mac.finalize().into_bytes();
        Ok(Signature { signature })
    }
}

impl<D: Digest + BlockSizeUser>
    Verifier<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>> for Hmac<D>
{
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>,
    ) -> Result<(), signature::Error> {
        let new_signature = self.try_sign(msg)?;
        if &new_signature != signature {
            return Err(signature::Error::new());
        }
        Ok(())
    }
}
