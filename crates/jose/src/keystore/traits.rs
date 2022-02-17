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

use std::{collections::HashSet, future::Future, sync::Arc};

use async_trait::async_trait;
use futures_util::{
    future::{Either, MapErr},
    TryFutureExt,
};
use mas_iana::jose::JsonWebSignatureAlg;
use thiserror::Error;

use crate::JwtHeader;

#[async_trait]
pub trait SigningKeystore {
    fn supported_algorithms(&self) -> HashSet<JsonWebSignatureAlg>;

    async fn prepare_header(&self, alg: JsonWebSignatureAlg) -> anyhow::Result<JwtHeader>;

    async fn sign(&self, header: &JwtHeader, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub trait VerifyingKeystore {
    type Error;
    type Future: Future<Output = Result<(), Self::Error>>;

    fn verify(&self, header: &JwtHeader, msg: &[u8], signature: &[u8]) -> Self::Future;
}

#[derive(Debug, Error)]
pub enum EitherError<A, B> {
    #[error(transparent)]
    Left(A),
    #[error(transparent)]
    Right(B),
}

impl<L, R> VerifyingKeystore for Either<L, R>
where
    L: VerifyingKeystore,
    R: VerifyingKeystore,
{
    type Error = EitherError<L::Error, R::Error>;

    #[allow(clippy::type_complexity)]
    type Future = Either<
        MapErr<L::Future, fn(L::Error) -> Self::Error>,
        MapErr<R::Future, fn(R::Error) -> Self::Error>,
    >;

    fn verify(&self, header: &JwtHeader, msg: &[u8], signature: &[u8]) -> Self::Future {
        match self {
            Either::Left(left) => Either::Left(
                left.verify(header, msg, signature)
                    .map_err(EitherError::Left),
            ),
            Either::Right(right) => Either::Right(
                right
                    .verify(header, msg, signature)
                    .map_err(EitherError::Right),
            ),
        }
    }
}

impl<T> VerifyingKeystore for Arc<T>
where
    T: VerifyingKeystore,
{
    type Error = T::Error;
    type Future = T::Future;

    fn verify(&self, header: &JwtHeader, msg: &[u8], signature: &[u8]) -> Self::Future {
        self.as_ref().verify(header, msg, signature)
    }
}
