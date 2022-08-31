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
    jwk::private_parameters::{EcPrivateParameters, JsonWebKeyPrivateParameters},
};

pub enum Signer {
    Hs256 { key: jwa::Hs256Key },
    Hs384 { key: jwa::Hs384Key },
    Hs512 { key: jwa::Hs512Key },
    Rs256 { key: jwa::Rs256SigningKey },
    Rs384 { key: jwa::Rs384SigningKey },
    Rs512 { key: jwa::Rs512SigningKey },
    Ps256 { key: jwa::Ps256SigningKey },
    Ps384 { key: jwa::Ps384SigningKey },
    Ps512 { key: jwa::Ps512SigningKey },
    Es256 { key: jwa::Es256SigningKey },
    Es384 { key: jwa::Es384SigningKey },
    Es256K { key: jwa::Es256KSigningKey },
}

impl From<jwa::Hs256Key> for Signer {
    fn from(key: jwa::Hs256Key) -> Self {
        Self::Hs256 { key }
    }
}

impl From<jwa::Hs384Key> for Signer {
    fn from(key: jwa::Hs384Key) -> Self {
        Self::Hs384 { key }
    }
}

impl From<jwa::Hs512Key> for Signer {
    fn from(key: jwa::Hs512Key) -> Self {
        Self::Hs512 { key }
    }
}

impl From<jwa::Rs256SigningKey> for Signer {
    fn from(key: jwa::Rs256SigningKey) -> Self {
        Self::Rs256 { key }
    }
}

impl From<jwa::Rs384SigningKey> for Signer {
    fn from(key: jwa::Rs384SigningKey) -> Self {
        Self::Rs384 { key }
    }
}

impl From<jwa::Rs512SigningKey> for Signer {
    fn from(key: jwa::Rs512SigningKey) -> Self {
        Self::Rs512 { key }
    }
}

impl From<jwa::Ps256SigningKey> for Signer {
    fn from(key: jwa::Ps256SigningKey) -> Self {
        Self::Ps256 { key }
    }
}

impl From<jwa::Ps384SigningKey> for Signer {
    fn from(key: jwa::Ps384SigningKey) -> Self {
        Self::Ps384 { key }
    }
}

impl From<jwa::Ps512SigningKey> for Signer {
    fn from(key: jwa::Ps512SigningKey) -> Self {
        Self::Ps512 { key }
    }
}

impl From<jwa::Es256SigningKey> for Signer {
    fn from(key: jwa::Es256SigningKey) -> Self {
        Self::Es256 { key }
    }
}

impl From<jwa::Es384SigningKey> for Signer {
    fn from(key: jwa::Es384SigningKey) -> Self {
        Self::Es384 { key }
    }
}

impl From<jwa::Es256KSigningKey> for Signer {
    fn from(key: jwa::Es256KSigningKey) -> Self {
        Self::Es256K { key }
    }
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
                Ok(Self::Rs256 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Rs384) => {
                Ok(Self::Rs384 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Rs512) => {
                Ok(Self::Rs512 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Ps256) => {
                Ok(Self::Ps256 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Ps384) => {
                Ok(Self::Ps384 {
                    key: params.try_into()?,
                })
            }

            (JsonWebKeyPrivateParameters::Rsa(params), JsonWebSignatureAlg::Ps512) => {
                Ok(Self::Ps512 {
                    key: params.try_into()?,
                })
            }

            (
                JsonWebKeyPrivateParameters::Ec(
                    params @ EcPrivateParameters {
                        crv: JsonWebKeyEcEllipticCurve::P256,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es256,
            ) => Ok(Self::Es256 {
                key: params.try_into()?,
            }),

            (
                JsonWebKeyPrivateParameters::Ec(
                    params @ EcPrivateParameters {
                        crv: JsonWebKeyEcEllipticCurve::P384,
                        ..
                    },
                ),
                JsonWebSignatureAlg::Es384,
            ) => Ok(Self::Es384 {
                key: params.try_into()?,
            }),

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
            ) => Ok(Self::Es256K {
                key: params.try_into()?,
            }),

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
