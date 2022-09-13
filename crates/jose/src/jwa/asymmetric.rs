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

use mas_iana::jose::{JsonWebKeyEcEllipticCurve, JsonWebSignatureAlg};
use rand::thread_rng;
use signature::RandomizedSigner;
use thiserror::Error;

use super::signature::Signature;
use crate::jwk::{JsonWebKeyPrivateParameters, JsonWebKeyPublicParameters};

#[derive(Debug, Error)]
pub enum AsymmetricKeyFromJwkError {
    #[error("Invalid RSA parameters")]
    Rsa {
        #[from]
        inner: rsa::errors::Error,
    },

    #[error("Invalid Elliptic Curve parameters")]
    Ecdsa {
        #[from]
        inner: ecdsa::Error,
    },

    #[error("Unsupported algorithm {alg}")]
    UnsupportedAlgorithm { alg: JsonWebSignatureAlg },

    #[error("Key not suitable for algorithm {alg}")]
    KeyNotSuitable { alg: JsonWebSignatureAlg },
}

/// An enum of all supported asymmetric signature algorithms verifying keys
#[non_exhaustive]
pub enum AsymmetricSigningKey {
    Rs256(super::Rs256SigningKey),
    Rs384(super::Rs384SigningKey),
    Rs512(super::Rs512SigningKey),
    Ps256(super::Ps256SigningKey),
    Ps384(super::Ps384SigningKey),
    Ps512(super::Ps512SigningKey),
    Es256(super::Es256SigningKey),
    Es384(super::Es384SigningKey),
    Es256K(super::Es256KSigningKey),
}

impl AsymmetricSigningKey {
    #[allow(dead_code)]
    pub fn from_jwk_and_alg(
        params: &JsonWebKeyPrivateParameters,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Self, AsymmetricKeyFromJwkError> {
        match (params, alg) {
            (JsonWebKeyPrivateParameters::Rsa(params), alg) => match alg {
                JsonWebSignatureAlg::Rs256 => Ok(Self::Rs256(params.try_into()?)),
                JsonWebSignatureAlg::Rs384 => Ok(Self::Rs384(params.try_into()?)),
                JsonWebSignatureAlg::Rs512 => Ok(Self::Rs512(params.try_into()?)),
                JsonWebSignatureAlg::Ps256 => Ok(Self::Ps256(params.try_into()?)),
                JsonWebSignatureAlg::Ps384 => Ok(Self::Ps384(params.try_into()?)),
                JsonWebSignatureAlg::Ps512 => Ok(Self::Ps512(params.try_into()?)),
                _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
            },

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es256)
                if params.crv == JsonWebKeyEcEllipticCurve::P256 =>
            {
                Ok(Self::Es256(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es384)
                if params.crv == JsonWebKeyEcEllipticCurve::P384 =>
            {
                Ok(Self::Es384(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es512)
                if params.crv == JsonWebKeyEcEllipticCurve::P521 =>
            {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es256K)
                if params.crv == JsonWebKeyEcEllipticCurve::Secp256K1 =>
            {
                Ok(Self::Es256K(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
        }
    }
}

impl From<super::Rs256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs256SigningKey) -> Self {
        Self::Rs256(key)
    }
}

impl From<super::Rs384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs384SigningKey) -> Self {
        Self::Rs384(key)
    }
}

impl From<super::Rs512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs512SigningKey) -> Self {
        Self::Rs512(key)
    }
}

impl From<super::Ps256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps256SigningKey) -> Self {
        Self::Ps256(key)
    }
}

impl From<super::Ps384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps384SigningKey) -> Self {
        Self::Ps384(key)
    }
}

impl From<super::Ps512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps512SigningKey) -> Self {
        Self::Ps512(key)
    }
}

impl From<super::Es256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es256SigningKey) -> Self {
        Self::Es256(key)
    }
}

impl From<super::Es384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es384SigningKey) -> Self {
        Self::Es384(key)
    }
}

impl From<super::Es256KSigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es256KSigningKey) -> Self {
        Self::Es256K(key)
    }
}

impl signature::Signer<Signature> for AsymmetricSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self {
            Self::Rs256(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Rs384(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Rs512(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps256(key) => {
                let signature = key.try_sign_with_rng(thread_rng(), msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps384(key) => {
                let signature = key.try_sign_with_rng(thread_rng(), msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps512(key) => {
                let signature = key.try_sign_with_rng(thread_rng(), msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es256(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es384(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es256K(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
        }
    }
}

/// An enum of all supported asymmetric signature algorithms signing keys
#[non_exhaustive]
pub enum AsymmetricVerifyingKey {
    Rs256(super::Rs256VerifyingKey),
    Rs384(super::Rs384VerifyingKey),
    Rs512(super::Rs512VerifyingKey),
    Ps256(super::Ps256VerifyingKey),
    Ps384(super::Ps384VerifyingKey),
    Ps512(super::Ps512VerifyingKey),
    Es256(super::Es256VerifyingKey),
    Es384(super::Es384VerifyingKey),
    Es256K(super::Es256KVerifyingKey),
}

impl AsymmetricVerifyingKey {
    pub fn from_jwk_and_alg(
        params: &JsonWebKeyPublicParameters,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Self, AsymmetricKeyFromJwkError> {
        match (params, alg) {
            (JsonWebKeyPublicParameters::Rsa(params), alg) => match alg {
                JsonWebSignatureAlg::Rs256 => Ok(Self::Rs256(params.try_into()?)),
                JsonWebSignatureAlg::Rs384 => Ok(Self::Rs384(params.try_into()?)),
                JsonWebSignatureAlg::Rs512 => Ok(Self::Rs512(params.try_into()?)),
                JsonWebSignatureAlg::Ps256 => Ok(Self::Ps256(params.try_into()?)),
                JsonWebSignatureAlg::Ps384 => Ok(Self::Ps384(params.try_into()?)),
                JsonWebSignatureAlg::Ps512 => Ok(Self::Ps512(params.try_into()?)),
                _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
            },

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es256)
                if params.crv == JsonWebKeyEcEllipticCurve::P256 =>
            {
                Ok(Self::Es256(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es384)
                if params.crv == JsonWebKeyEcEllipticCurve::P384 =>
            {
                Ok(Self::Es384(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es512)
                if params.crv == JsonWebKeyEcEllipticCurve::P521 =>
            {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es256K)
                if params.crv == JsonWebKeyEcEllipticCurve::Secp256K1 =>
            {
                Ok(Self::Es256K(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
        }
    }
}

impl From<super::Rs256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs256VerifyingKey) -> Self {
        Self::Rs256(key)
    }
}

impl From<super::Rs384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs384VerifyingKey) -> Self {
        Self::Rs384(key)
    }
}

impl From<super::Rs512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs512VerifyingKey) -> Self {
        Self::Rs512(key)
    }
}

impl From<super::Ps256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps256VerifyingKey) -> Self {
        Self::Ps256(key)
    }
}

impl From<super::Ps384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps384VerifyingKey) -> Self {
        Self::Ps384(key)
    }
}

impl From<super::Ps512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps512VerifyingKey) -> Self {
        Self::Ps512(key)
    }
}

impl From<super::Es256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es256VerifyingKey) -> Self {
        Self::Es256(key)
    }
}

impl From<super::Es384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es384VerifyingKey) -> Self {
        Self::Es384(key)
    }
}

impl From<super::Es256KVerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es256KVerifyingKey) -> Self {
        Self::Es256K(key)
    }
}

impl signature::Verifier<Signature> for AsymmetricVerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ecdsa::Error> {
        match self {
            Self::Rs256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Rs384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Rs512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es256K(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
        }
    }
}
