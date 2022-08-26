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

use crate::jwk::{public_parameters::EcPublicParameters, JsonWebKeyParameters};

pub enum Verifier {
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
        key: crate::rsa::pkcs1v15::VerifyingKey<Sha256>,
    },
    Rs384 {
        key: crate::rsa::pkcs1v15::VerifyingKey<Sha384>,
    },
    Rs512 {
        key: crate::rsa::pkcs1v15::VerifyingKey<Sha512>,
    },
    Ps256 {
        key: crate::rsa::pss::VerifyingKey<Sha256>,
    },
    Ps384 {
        key: crate::rsa::pss::VerifyingKey<Sha384>,
    },
    Ps512 {
        key: crate::rsa::pss::VerifyingKey<Sha512>,
    },
    Es256 {
        key: ecdsa::VerifyingKey<p256::NistP256>,
    },
    Es384 {
        key: ecdsa::VerifyingKey<p384::NistP384>,
    },
    Es256K {
        key: ecdsa::VerifyingKey<k256::Secp256k1>,
    },
}

#[derive(Debug, Error)]
pub enum VerifierFromJwkError {
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

    #[error("invalid curve parameter X")]
    InvalidCurveParameterX,

    #[error("invalid curve parameter Y")]
    InvalidCurveParameterY,

    #[error("algorithm {algorithm} is not supported")]
    UnsupportedAlgorithm { algorithm: JsonWebSignatureAlg },

    #[error("key is not suitable for algorithm {algorithm}")]
    KeyNotSuitable { algorithm: JsonWebSignatureAlg },
}
#[derive(Debug, Error)]
pub enum VerifierFromOctError {
    #[error("algorithm {algorithm} is not supported")]
    UnsupportedAlgorithm { algorithm: JsonWebSignatureAlg },
}

impl Verifier {
    pub fn for_oct_and_alg(
        key: Vec<u8>,
        alg: JsonWebSignatureAlg,
    ) -> Result<Self, VerifierFromOctError> {
        match alg {
            JsonWebSignatureAlg::Hs256 => Ok(Self::Hs256 { key: key.into() }),
            JsonWebSignatureAlg::Hs384 => Ok(Self::Hs384 { key: key.into() }),
            JsonWebSignatureAlg::Hs512 => Ok(Self::Hs512 { key: key.into() }),
            algorithm => Err(VerifierFromOctError::UnsupportedAlgorithm { algorithm }),
        }
    }

    pub fn for_jwk_and_alg(
        key: &JsonWebKeyParameters,
        alg: JsonWebSignatureAlg,
    ) -> Result<Self, VerifierFromJwkError> {
        match (key, alg) {
            (JsonWebKeyParameters::Rsa(params), JsonWebSignatureAlg::Rs256) => {
                let key = rsa::RsaPublicKey::try_from(params)?;
                Ok(Self::Rs256 { key: key.into() })
            }

            (JsonWebKeyParameters::Rsa(params), JsonWebSignatureAlg::Rs384) => {
                let key = rsa::RsaPublicKey::try_from(params)?;
                Ok(Self::Rs384 { key: key.into() })
            }

            (JsonWebKeyParameters::Rsa(params), JsonWebSignatureAlg::Rs512) => {
                let key = rsa::RsaPublicKey::try_from(params)?;
                Ok(Self::Rs512 { key: key.into() })
            }

            (JsonWebKeyParameters::Rsa(params), JsonWebSignatureAlg::Ps256) => {
                let key = rsa::RsaPublicKey::try_from(params)?;
                Ok(Self::Ps256 { key: key.into() })
            }

            (JsonWebKeyParameters::Rsa(params), JsonWebSignatureAlg::Ps384) => {
                let key = rsa::RsaPublicKey::try_from(params)?;
                Ok(Self::Ps384 { key: key.into() })
            }

            (JsonWebKeyParameters::Rsa(params), JsonWebSignatureAlg::Ps512) => {
                let key = rsa::RsaPublicKey::try_from(params)?;
                Ok(Self::Ps512 { key: key.into() })
            }

            (
                JsonWebKeyParameters::Ec(
                    params @ EcPublicParameters {
                        crv: JsonWebKeyEcEllipticCurve::P256,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256,
            ) => {
                let key = ecdsa::VerifyingKey::try_from(params)?;
                Ok(Self::Es256 { key })
            }

            (
                JsonWebKeyParameters::Ec(
                    params @ EcPublicParameters {
                        crv: JsonWebKeyEcEllipticCurve::P384,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es384,
            ) => {
                let key = ecdsa::VerifyingKey::try_from(params)?;
                Ok(Self::Es384 { key })
            }

            (
                JsonWebKeyParameters::Ec(EcPublicParameters {
                    crv: JsonWebKeyEcEllipticCurve::P521,
                    ..
                }),
                JsonWebSignatureAlg::Es512,
            ) => Err(VerifierFromJwkError::UnsupportedAlgorithm {
                algorithm: JsonWebSignatureAlg::Es512,
            }),

            (
                JsonWebKeyParameters::Ec(
                    params @ EcPublicParameters {
                        crv: JsonWebKeyEcEllipticCurve::Secp256K1,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256K,
            ) => {
                let key = ecdsa::VerifyingKey::try_from(params)?;
                Ok(Self::Es256K { key })
            }

            (JsonWebKeyParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
                Err(VerifierFromJwkError::UnsupportedAlgorithm {
                    algorithm: JsonWebSignatureAlg::EdDsa,
                })
            }

            (_, algorithm) => Err(VerifierFromJwkError::KeyNotSuitable { algorithm }),
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

impl signature::Verifier<GenericSignature> for Verifier {
    fn verify(&self, msg: &[u8], signature: &GenericSignature) -> Result<(), signature::Error> {
        match self {
            Verifier::Hs256 { key } => {
                let signature = crate::hmac::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Hs384 { key } => {
                let signature = crate::hmac::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Hs512 { key } => {
                let signature = crate::hmac::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Rs256 { key } => {
                let signature = rsa::pkcs1v15::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Rs384 { key } => {
                let signature = rsa::pkcs1v15::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Rs512 { key } => {
                let signature = rsa::pkcs1v15::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Ps256 { key } => {
                let signature = rsa::pss::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Ps384 { key } => {
                let signature = rsa::pss::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Ps512 { key } => {
                let signature = rsa::pss::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Es256 { key } => {
                let signature = ecdsa::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Es384 { key } => {
                let signature = ecdsa::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Es256K { key } => {
                let signature = ecdsa::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
        }
    }
}
