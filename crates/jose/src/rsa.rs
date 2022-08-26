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

pub(crate) mod pkcs1v15 {
    use std::marker::PhantomData;

    use digest::Digest;
    use rsa::RsaPublicKey;
    use sha2::{Sha256, Sha384, Sha512};

    pub struct VerifyingKey<H> {
        inner: rsa::pkcs1v15::VerifyingKey,
        hash: PhantomData<H>,
    }

    impl From<RsaPublicKey> for VerifyingKey<Sha256> {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pkcs1v15::VerifyingKey::new_with_hash(key, rsa::Hash::SHA2_256);
            ensure_verifier(Self {
                inner,
                hash: PhantomData::default(),
            })
        }
    }

    impl From<RsaPublicKey> for VerifyingKey<Sha384> {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pkcs1v15::VerifyingKey::new_with_hash(key, rsa::Hash::SHA2_384);
            ensure_verifier(Self {
                inner,
                hash: PhantomData::default(),
            })
        }
    }

    impl From<RsaPublicKey> for VerifyingKey<Sha512> {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pkcs1v15::VerifyingKey::new_with_hash(key, rsa::Hash::SHA2_512);
            ensure_verifier(Self {
                inner,
                hash: PhantomData::default(),
            })
        }
    }

    #[inline]
    fn ensure_verifier<T>(t: T) -> T
    where
        T: signature::Verifier<rsa::pkcs1v15::Signature>,
    {
        t
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
}

pub(crate) mod pss {
    use std::marker::PhantomData;

    use digest::Digest;
    use rsa::RsaPublicKey;
    use sha2::{Sha256, Sha384, Sha512};

    pub struct VerifyingKey<H> {
        inner: rsa::pss::VerifyingKey,
        hash: PhantomData<H>,
    }

    impl From<RsaPublicKey> for VerifyingKey<Sha256> {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pss::VerifyingKey::new(key, Box::new(Sha256::new()));
            ensure_verifier(Self {
                inner,
                hash: PhantomData::default(),
            })
        }
    }

    impl From<RsaPublicKey> for VerifyingKey<Sha384> {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pss::VerifyingKey::new(key, Box::new(Sha384::new()));
            ensure_verifier(Self {
                inner,
                hash: PhantomData::default(),
            })
        }
    }

    impl From<RsaPublicKey> for VerifyingKey<Sha512> {
        fn from(key: RsaPublicKey) -> Self {
            let inner = rsa::pss::VerifyingKey::new(key, Box::new(Sha512::new()));
            ensure_verifier(Self {
                inner,
                hash: PhantomData::default(),
            })
        }
    }

    #[inline]
    fn ensure_verifier<T>(t: T) -> T
    where
        T: signature::Verifier<rsa::pss::Signature>,
    {
        t
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
}
