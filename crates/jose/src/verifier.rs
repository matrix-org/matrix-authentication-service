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
use signature::Signature;
use thiserror::Error;

use crate::{
    jwa,
    jwk::{public_parameters::EcPublicParameters, JsonWebKeyPublicParameters},
};

pub enum Verifier {
    Hs256 { key: jwa::Hs256Key },
    Hs384 { key: jwa::Hs384Key },
    Hs512 { key: jwa::Hs512Key },
    Rs256 { key: jwa::Rs256VerifyingKey },
    Rs384 { key: jwa::Rs384VerifyingKey },
    Rs512 { key: jwa::Rs512VerifyingKey },
    Ps256 { key: jwa::Ps256VerifyingKey },
    Ps384 { key: jwa::Ps384VerifyingKey },
    Ps512 { key: jwa::Ps512VerifyingKey },
    Es256 { key: jwa::Es256VerifyingKey },
    Es384 { key: jwa::Es384VerifyingKey },
    Es256K { key: jwa::Es256KVerifyingKey },
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
        key: &JsonWebKeyPublicParameters,
        alg: JsonWebSignatureAlg,
    ) -> Result<Self, VerifierFromJwkError> {
        match (key, alg) {
            (JsonWebKeyPublicParameters::Rsa(params), JsonWebSignatureAlg::Rs256) => {
                Ok(Self::Rs256 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPublicParameters::Rsa(params), JsonWebSignatureAlg::Rs384) => {
                Ok(Self::Rs384 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPublicParameters::Rsa(params), JsonWebSignatureAlg::Rs512) => {
                Ok(Self::Rs512 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPublicParameters::Rsa(params), JsonWebSignatureAlg::Ps256) => {
                Ok(Self::Ps256 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPublicParameters::Rsa(params), JsonWebSignatureAlg::Ps384) => {
                Ok(Self::Ps384 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPublicParameters::Rsa(params), JsonWebSignatureAlg::Ps512) => {
                Ok(Self::Ps512 {
                    key: params.try_into()?,
                })
            }

            (
                JsonWebKeyPublicParameters::Ec(
                    params @ EcPublicParameters {
                        crv: JsonWebKeyEcEllipticCurve::P256,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256,
            ) => Ok(Self::Es256 {
                key: params.try_into()?,
            }),

            (
                JsonWebKeyPublicParameters::Ec(
                    params @ EcPublicParameters {
                        crv: JsonWebKeyEcEllipticCurve::P384,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es384,
            ) => Ok(Self::Es384 {
                key: params.try_into()?,
            }),

            (
                JsonWebKeyPublicParameters::Ec(EcPublicParameters {
                    crv: JsonWebKeyEcEllipticCurve::P521,
                    ..
                }),
                JsonWebSignatureAlg::Es512,
            ) => Err(VerifierFromJwkError::UnsupportedAlgorithm {
                algorithm: JsonWebSignatureAlg::Es512,
            }),

            (
                JsonWebKeyPublicParameters::Ec(
                    params @ EcPublicParameters {
                        crv: JsonWebKeyEcEllipticCurve::Secp256K1,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256K,
            ) => Ok(Self::Es256K {
                key: params.try_into()?,
            }),

            (JsonWebKeyPublicParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
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
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Hs384 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Hs512 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Rs256 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Rs384 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Rs512 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Ps256 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Ps384 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Ps512 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Es256 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Es384 { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
            Verifier::Es256K { key } => {
                let signature = signature::Signature::from_bytes(signature.as_bytes())?;
                key.verify(msg, &signature)?;
                Ok(())
            }
        }
    }
}
