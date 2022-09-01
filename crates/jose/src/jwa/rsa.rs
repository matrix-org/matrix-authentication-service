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

// This is a temporary wrapper until the RSA crate actually hashes the input
// See <https://github.com/RustCrypto/RSA/pull/174#issuecomment-1227330296>

use super::signature::Signature;

pub(crate) trait RsaHashIdentifier {
    const HASH: rsa::Hash;
}

impl RsaHashIdentifier for sha2::Sha224 {
    const HASH: rsa::Hash = rsa::Hash::SHA2_224;
}

impl RsaHashIdentifier for sha2::Sha256 {
    const HASH: rsa::Hash = rsa::Hash::SHA2_256;
}

impl RsaHashIdentifier for sha2::Sha384 {
    const HASH: rsa::Hash = rsa::Hash::SHA2_384;
}

impl RsaHashIdentifier for sha2::Sha512 {
    const HASH: rsa::Hash = rsa::Hash::SHA2_512;
}

pub(crate) mod pkcs1v15 {
    use std::marker::PhantomData;

    use digest::Digest;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

    use super::{RsaHashIdentifier, Signature};

    pub struct VerifyingKey<H> {
        inner: RsaPublicKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPublicKey> for VerifyingKey<H> {
        fn from(inner: RsaPublicKey) -> Self {
            Self {
                inner,
                hash: PhantomData,
            }
        }
    }

    impl<H> signature::Verifier<Signature> for VerifyingKey<H>
    where
        H: Digest + RsaHashIdentifier,
    {
        fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
            let digest = H::digest(msg);
            let padding = PaddingScheme::new_pkcs1v15_sign(Some(H::HASH));
            self.inner
                .verify(padding, &digest, signature.as_ref())
                .map_err(signature::Error::from_source)
        }
    }

    pub struct SigningKey<H> {
        inner: RsaPrivateKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPrivateKey> for SigningKey<H> {
        fn from(inner: RsaPrivateKey) -> Self {
            Self {
                inner,
                hash: PhantomData,
            }
        }
    }

    impl<H> signature::Signer<Signature> for SigningKey<H>
    where
        H: Digest + RsaHashIdentifier,
    {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
            let digest = H::digest(msg);
            let padding = PaddingScheme::new_pkcs1v15_sign(Some(H::HASH));
            self.inner
                .sign(padding, &digest)
                .map_err(signature::Error::from_source)
                .map(Signature::new)
        }
    }
}

pub(crate) mod pss {
    use std::marker::PhantomData;

    use digest::{Digest, DynDigest};
    use rand::thread_rng;
    use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

    use super::Signature;

    pub struct VerifyingKey<H> {
        inner: RsaPublicKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPublicKey> for VerifyingKey<H> {
        fn from(inner: RsaPublicKey) -> Self {
            Self {
                inner,
                hash: PhantomData,
            }
        }
    }

    impl<H> signature::Verifier<Signature> for VerifyingKey<H>
    where
        H: Digest + DynDigest + 'static,
    {
        fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
            let digest = H::digest(msg);
            let padding = PaddingScheme::new_pss::<H, _>(thread_rng());
            self.inner
                .verify(padding, &digest, signature.as_ref())
                .map_err(signature::Error::from_source)
        }
    }

    pub struct SigningKey<H> {
        inner: RsaPrivateKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPrivateKey> for SigningKey<H> {
        fn from(inner: RsaPrivateKey) -> Self {
            Self {
                inner,
                hash: PhantomData,
            }
        }
    }

    impl<H> signature::Signer<Signature> for SigningKey<H>
    where
        H: Digest + DynDigest + 'static,
    {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
            let digest = H::digest(msg);
            let padding = PaddingScheme::new_pss::<H, _>(thread_rng());
            self.inner
                .sign(padding, &digest)
                .map_err(signature::Error::from_source)
                .map(Signature::new)
        }
    }
}
