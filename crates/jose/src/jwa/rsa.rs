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

pub trait RsaHashIdentifier {
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
    use rsa::{RsaPrivateKey, RsaPublicKey};

    use super::RsaHashIdentifier;

    pub struct VerifyingKey<H> {
        inner: rsa::pkcs1v15::VerifyingKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPublicKey> for VerifyingKey<H>
    where
        H: RsaHashIdentifier,
    {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pkcs1v15::VerifyingKey::new_with_hash(key, H::HASH);
            Self {
                inner,
                hash: PhantomData::default(),
            }
        }
    }

    impl<H> signature::Verifier<rsa::pkcs1v15::Signature> for VerifyingKey<H>
    where
        H: Digest,
    {
        fn verify(
            &self,
            msg: &[u8],
            signature: &rsa::pkcs1v15::Signature,
        ) -> Result<(), signature::Error> {
            let digest = H::digest(msg);
            self.inner.verify(&digest, signature)
        }
    }

    pub struct SigningKey<H> {
        inner: rsa::pkcs1v15::SigningKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPrivateKey> for SigningKey<H>
    where
        H: RsaHashIdentifier,
    {
        fn from(key: RsaPrivateKey) -> Self {
            let inner = rsa::pkcs1v15::SigningKey::new_with_hash(key, H::HASH);
            Self {
                inner,
                hash: PhantomData::default(),
            }
        }
    }

    impl<H> signature::Signer<rsa::pkcs1v15::Signature> for SigningKey<H>
    where
        H: Digest,
    {
        fn try_sign(&self, msg: &[u8]) -> Result<rsa::pkcs1v15::Signature, signature::Error> {
            let digest = H::digest(msg);
            self.inner.try_sign(&digest)
        }
    }
}

pub(crate) mod pss {
    use std::marker::PhantomData;

    use digest::{Digest, DynDigest};
    use rand::thread_rng;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use signature::RandomizedSigner;

    pub struct VerifyingKey<H> {
        inner: rsa::pss::VerifyingKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPublicKey> for VerifyingKey<H>
    where
        H: DynDigest + Default + 'static,
    {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pss::VerifyingKey::new(key, Box::new(H::default()));
            Self {
                inner,
                hash: PhantomData::default(),
            }
        }
    }

    impl<H> signature::Verifier<rsa::pss::Signature> for VerifyingKey<H>
    where
        H: Digest,
    {
        fn verify(
            &self,
            msg: &[u8],
            signature: &rsa::pss::Signature,
        ) -> Result<(), signature::Error> {
            let digest = H::digest(msg);
            self.inner.verify(&digest, signature)
        }
    }

    pub struct SigningKey<H> {
        inner: rsa::pss::SigningKey,
        hash: PhantomData<H>,
    }

    impl<H> From<RsaPrivateKey> for SigningKey<H>
    where
        H: DynDigest + Default + 'static,
    {
        fn from(key: RsaPrivateKey) -> Self {
            let inner = rsa::pss::SigningKey::new(key, Box::new(H::default()));
            Self {
                inner,
                hash: PhantomData::default(),
            }
        }
    }

    impl<H> signature::Signer<rsa::pss::Signature> for SigningKey<H>
    where
        H: Digest,
    {
        fn try_sign(&self, msg: &[u8]) -> Result<rsa::pss::Signature, signature::Error> {
            let digest = H::digest(msg);
            self.inner.try_sign_with_rng(thread_rng(), &digest)
        }
    }
}
