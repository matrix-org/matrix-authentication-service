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
use sha2::{Sha256, Sha384, Sha512};
use signature::Signature;
use thiserror::Error;

use crate::jwk::private_parameters::{EcPrivateParameters, JsonWebKeyPrivateParameters};

pub enum Signer {
    Hs256 {
        key: crate::hmac::Hmac<Sha256>,
    },
    Hs384 {
        key: crate::hmac::Hmac<Sha384>,
    },
    Hs512 {
        key: crate::hmac::Hmac<Sha512>,
    },
    Rs256 {
        key: crate::rsa::pkcs1v15::SigningKey<Sha256>,
    },
    Rs384 {
        key: crate::rsa::pkcs1v15::SigningKey<Sha384>,
    },
    Rs512 {
        key: crate::rsa::pkcs1v15::SigningKey<Sha512>,
    },
    Ps256 {
        key: crate::rsa::pss::SigningKey<Sha256>,
    },
    Ps384 {
        key: crate::rsa::pss::SigningKey<Sha384>,
    },
    Ps512 {
        key: crate::rsa::pss::SigningKey<Sha512>,
    },
    Es256 {
        key: ecdsa::SigningKey<p256::NistP256>,
    },
    Es384 {
        key: ecdsa::SigningKey<p384::NistP384>,
    },
    Es256K {
        key: ecdsa::SigningKey<k256::Secp256k1>,
    },
}

#[derive(Debug, Error)]
pub enum SignerFromJwkError {
    #[error("invalid RSA key")]
    InvalidRsaKey {
        #[from]
        inner: rsa::errors::Error,
    },

    #[error("invalid elliptic curve key")]
    InvalidEcKey {
        #[from]
        inner: ecdsa::Error,
    },

    #[error("algorithm {algorithm} is not supported")]
    UnsupportedAlgorithm { algorithm: JsonWebSignatureAlg },

    #[error("key is not suitable for algorithm {algorithm}")]
    KeyNotSuitable { algorithm: JsonWebSignatureAlg },
}

#[derive(Debug, Error)]
pub enum SignerFromOctError {
    #[error("algorithm {algorithm} is not supported")]
    UnsupportedAlgorithm { algorithm: JsonWebSignatureAlg },
}

impl Signer {
    pub fn for_oct_and_alg(
        key: Vec<u8>,
        alg: JsonWebSignatureAlg,
    ) -> Result<Self, SignerFromOctError> {
        match alg {
            JsonWebSignatureAlg::Hs256 => Ok(Self::Hs256 { key: key.into() }),
            JsonWebSignatureAlg::Hs384 => Ok(Self::Hs384 { key: key.into() }),
            JsonWebSignatureAlg::Hs512 => Ok(Self::Hs512 { key: key.into() }),
            algorithm => Err(SignerFromOctError::UnsupportedAlgorithm { algorithm }),
        }
    }

    pub fn for_jwk_and_alg(
        key: &JsonWebKeyPrivateParameters,
        alg: JsonWebSignatureAlg,
    ) -> Result<Self, SignerFromJwkError> {
        match (key, alg) {
            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Rs256) => {
                let key: rsa::RsaPrivateKey = params.try_into()?;
                Ok(Self::Rs256 { key: key.into() })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Rs384) => {
                let key: rsa::RsaPrivateKey = params.try_into()?;
                Ok(Self::Rs384 { key: key.into() })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Rs512) => {
                let key: rsa::RsaPrivateKey = params.try_into()?;
                Ok(Self::Rs512 { key: key.into() })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Ps256) => {
                let key: rsa::RsaPrivateKey = params.try_into()?;
                Ok(Self::Ps256 { key: key.into() })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Ps384) => {
                let key: rsa::RsaPrivateKey = params.try_into()?;
                Ok(Self::Ps384 { key: key.into() })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Ps512) => {
                let key: rsa::RsaPrivateKey = params.try_into()?;
                Ok(Self::Ps512 { key: key.into() })
            }

            (
                JsonWebKeyPrivateParameters::Ec(
                    params @ EcPrivateParameters {
                        crv: JsonWebKeyEcEllipticCurve::P256,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256,
            ) => {
                let key = ecdsa::SigningKey::try_from(params)?;
                Ok(Self::Es256 { key })
            }

            (
                JsonWebKeyPrivateParameters::Ec(
                    params @ EcPrivateParameters {
                        crv: JsonWebKeyEcEllipticCurve::P384,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es384,
            ) => {
                let key = ecdsa::SigningKey::try_from(params)?;
                Ok(Self::Es384 { key })
            }

            (
                JsonWebKeyPrivateParameters::Ec(EcPrivateParameters {
                    crv: JsonWebKeyEcEllipticCurve::P521,
                    ..
                }),
                JsonWebSignatureAlg::Es512,
            ) => Err(SignerFromJwkError::UnsupportedAlgorithm {
                algorithm: JsonWebSignatureAlg::Es512,
            }),

            (
                JsonWebKeyPrivateParameters::Ec(
                    params @ EcPrivateParameters {
                        crv: JsonWebKeyEcEllipticCurve::Secp256K1,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256K,
            ) => {
                let key = ecdsa::SigningKey::try_from(params)?;
                Ok(Self::Es256K { key })
            }

            (JsonWebKeyPrivateParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
                Err(SignerFromJwkError::UnsupportedAlgorithm {
                    algorithm: JsonWebSignatureAlg::EdDsa,
                })
            }

            (_, algorithm) => Err(SignerFromJwkError::KeyNotSuitable { algorithm }),
        }
    }
}

#[derive(Debug)]
pub struct GenericSignature {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for GenericSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl signature::Signature for GenericSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl signature::Signer<GenericSignature> for Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<GenericSignature, signature::Error> {
        match self {
            Signer::Hs256 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Hs384 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Hs512 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Rs256 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Rs384 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Rs512 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Ps256 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Ps384 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Ps512 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Es256 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Es384 { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
            Signer::Es256K { key } => {
                let signature = key.try_sign(msg)?;
                GenericSignature::from_bytes(signature.as_bytes())
            }
        }
    }
}
