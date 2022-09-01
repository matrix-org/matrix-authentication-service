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

//! A crate to store keys which can then be used to sign and verify JWTs.

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::broken_intra_doc_links,
    rustdoc::all
)]
#![warn(clippy::pedantic)]

use std::{ops::Deref, sync::Arc};

use der::{zeroize::Zeroizing, Decode};
use mas_iana::jose::{JsonWebKeyType, JsonWebSignatureAlg};
pub use mas_jose::jwk::{JsonWebKey, JsonWebKeySet};
use mas_jose::{
    jwa::{AsymmetricSigningKey, AsymmetricVerifyingKey},
    jwk::{JsonWebKeyPublicParameters, ParametersInfo, PublicJsonWebKeySet},
};
use pem_rfc7468::PemLabel;
use pkcs1::EncodeRsaPrivateKey;
use pkcs8::{AssociatedOid, PrivateKeyInfo};
use rand::{CryptoRng, RngCore};
use rsa::BigUint;
use sec1::EncodeEcPrivateKey;
use thiserror::Error;

mod encrypter;

pub use self::encrypter::Encrypter;

/// Error type used when a key could not be loaded
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to read PEM document")]
    Pem {
        #[from]
        inner: pem_rfc7468::Error,
    },

    #[error("Invalid RSA private key")]
    Rsa {
        #[from]
        inner: rsa::errors::Error,
    },

    #[error("Failed to decode PKCS1-encoded RSA key")]
    Pkcs1 {
        #[from]
        inner: pkcs1::Error,
    },

    #[error("Failed to decode PKCS8-encoded key")]
    Pkcs8 {
        #[from]
        inner: pkcs8::Error,
    },

    #[error(transparent)]
    Der {
        #[from]
        inner: der::Error,
    },

    #[error(transparent)]
    Spki {
        #[from]
        inner: spki::Error,
    },

    #[error("Unknown Elliptic Curve OID {oid}")]
    UnknownEllipticCurveOid { oid: const_oid::ObjectIdentifier },

    #[error("Unknown algorithm OID {oid}")]
    UnknownAlgorithmOid { oid: const_oid::ObjectIdentifier },

    #[error("Unsupported PEM label {label:?}")]
    UnsupportedPemLabel { label: String },

    #[error("Missing parameters in SEC1 key")]
    MissingSec1Parameters,

    #[error("Missing curve name in SEC1 parameters")]
    MissingSec1CurveName,

    #[error("Key is encrypted and no password was provided")]
    Encrypted,

    #[error("Key is not encrypted but a password was provided")]
    Unencrypted,

    #[error("Unsupported format")]
    UnsupportedFormat,

    #[error("Could not decode encrypted payload")]
    InEncrypted {
        #[source]
        inner: Box<LoadError>,
    },
}

/// A single private key
#[non_exhaustive]
pub enum PrivateKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    EcP256(Box<elliptic_curve::SecretKey<p256::NistP256>>),
    EcP384(Box<elliptic_curve::SecretKey<p384::NistP384>>),
    EcK256(Box<elliptic_curve::SecretKey<k256::Secp256k1>>),
}

/// Error returned when the key can't be used for the requested algorithm
#[derive(Debug, Error)]
#[error("Wrong algorithm for key")]
pub struct WrongAlgorithmError;

impl PrivateKey {
    fn from_pkcs1_private_key(pkcs1_key: &pkcs1::RsaPrivateKey) -> Result<Self, LoadError> {
        // Taken from `TryFrom<pkcs8::PrivateKeyInfo<'_>> for RsaPrivateKey`

        // Multi-prime RSA keys not currently supported
        if pkcs1_key.version() != pkcs1::Version::TwoPrime {
            return Err(pkcs1::Error::Version.into());
        }

        let n = BigUint::from_bytes_be(pkcs1_key.modulus.as_bytes());
        let e = BigUint::from_bytes_be(pkcs1_key.public_exponent.as_bytes());
        let d = BigUint::from_bytes_be(pkcs1_key.private_exponent.as_bytes());
        let first_prime = BigUint::from_bytes_be(pkcs1_key.prime1.as_bytes());
        let second_prime = BigUint::from_bytes_be(pkcs1_key.prime2.as_bytes());
        let primes = vec![first_prime, second_prime];
        let key = rsa::RsaPrivateKey::from_components(n, e, d, primes);
        Ok(Self::Rsa(Box::new(key)))
    }

    fn from_private_key_info(info: PrivateKeyInfo) -> Result<Self, LoadError> {
        match info.algorithm.oid {
            pkcs1::ALGORITHM_OID => Ok(Self::Rsa(Box::new(info.try_into()?))),
            elliptic_curve::ALGORITHM_OID => match info.algorithm.parameters_oid()? {
                p256::NistP256::OID => Ok(Self::EcP256(Box::new(info.try_into()?))),
                p384::NistP384::OID => Ok(Self::EcP384(Box::new(info.try_into()?))),
                k256::Secp256k1::OID => Ok(Self::EcK256(Box::new(info.try_into()?))),
                oid => Err(LoadError::UnknownEllipticCurveOid { oid }),
            },
            oid => Err(LoadError::UnknownAlgorithmOid { oid }),
        }
    }

    fn from_ec_private_key(key: sec1::EcPrivateKey) -> Result<Self, LoadError> {
        let curve = key
            .parameters
            .ok_or(LoadError::MissingSec1Parameters)?
            .named_curve()
            .ok_or(LoadError::MissingSec1CurveName)?;

        match curve {
            p256::NistP256::OID => Ok(Self::EcP256(Box::new(key.try_into()?))),
            p384::NistP384::OID => Ok(Self::EcP384(Box::new(key.try_into()?))),
            k256::Secp256k1::OID => Ok(Self::EcK256(Box::new(key.try_into()?))),
            oid => Err(LoadError::UnknownEllipticCurveOid { oid }),
        }
    }

    /// Serialize the key as a DER document
    ///
    /// It will use the most common format depending on the key type: PKCS1 for
    /// RSA keys and SEC1 for elliptic curve keys
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding failed
    pub fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, anyhow::Error> {
        let der = match self {
            PrivateKey::Rsa(key) => key.to_pkcs1_der()?.to_bytes(),
            PrivateKey::EcP256(key) => key.to_sec1_der()?,
            PrivateKey::EcP384(key) => key.to_sec1_der()?,
            PrivateKey::EcK256(key) => key.to_sec1_der()?,
        };

        Ok(der)
    }

    /// Serialize the key as a PEM document
    ///
    /// It will use the most common format depending on the key type: PKCS1 for
    /// RSA keys and SEC1 for elliptic curve keys
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding failed
    pub fn to_pem(
        &self,
        line_ending: pem_rfc7468::LineEnding,
    ) -> Result<Zeroizing<String>, anyhow::Error> {
        let pem = match self {
            PrivateKey::Rsa(key) => key.to_pkcs1_pem(line_ending)?,
            PrivateKey::EcP256(key) => key.to_sec1_pem(line_ending)?,
            PrivateKey::EcP384(key) => key.to_sec1_pem(line_ending)?,
            PrivateKey::EcK256(key) => key.to_sec1_pem(line_ending)?,
        };

        Ok(pem)
    }

    /// Load an unencrypted PEM or DER encoded key
    ///
    /// # Errors
    ///
    /// Returns the same kind of errors as [`Self::load_pem`] and
    /// [`Self::load_der`].
    pub fn load(bytes: &[u8]) -> Result<Self, LoadError> {
        if let Ok(pem) = std::str::from_utf8(bytes) {
            match Self::load_pem(pem) {
                Ok(s) => return Ok(s),
                // If there was an error loading the document as PEM, ignore it and continue by
                // trying to load it as DER
                Err(LoadError::Pem { .. }) => {}
                Err(e) => return Err(e),
            }
        }

        Self::load_der(bytes)
    }

    /// Load an encrypted PEM or DER encoded key, and decrypt it with the given
    /// password
    ///
    /// # Errors
    ///
    /// Returns the same kind of errors as [`Self::load_encrypted_pem`] and
    /// [`Self::load_encrypted_der`].
    pub fn load_encrypted(bytes: &[u8], password: impl AsRef<[u8]>) -> Result<Self, LoadError> {
        if let Ok(pem) = std::str::from_utf8(bytes) {
            match Self::load_encrypted_pem(pem, password.as_ref()) {
                Ok(s) => return Ok(s),
                // If there was an error loading the document as PEM, ignore it and continue by
                // trying to load it as DER
                Err(LoadError::Pem { .. }) => {}
                Err(e) => return Err(e),
            }
        }

        Self::load_encrypted_der(bytes, password)
    }

    /// Load an encrypted key from DER-encoded bytes, and decrypt it with the
    /// given password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the key is in an non-encrypted format
    ///   - the key could not be decrypted
    ///   - the PKCS8 key could not be loaded
    pub fn load_encrypted_der(der: &[u8], password: impl AsRef<[u8]>) -> Result<Self, LoadError> {
        if let Ok(info) = pkcs8::EncryptedPrivateKeyInfo::from_der(der) {
            let decrypted = info.decrypt(password)?;
            return Self::load_der(decrypted.as_bytes()).map_err(|inner| LoadError::InEncrypted {
                inner: Box::new(inner),
            });
        }

        if pkcs8::PrivateKeyInfo::from_der(der).is_ok()
            || sec1::EcPrivateKey::from_der(der).is_ok()
            || pkcs1::RsaPrivateKey::from_der(der).is_ok()
        {
            return Err(LoadError::Encrypted);
        }

        Err(LoadError::UnsupportedFormat)
    }

    /// Load an unencrypted key from DER-encoded bytes
    ///
    /// It tries to decode the bytes from the various known DER formats (PKCS8,
    /// SEC1 and PKCS1, in that order), and return the first one that works.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the PKCS8 key is encrypted
    ///   - none of the formats could be decoded
    ///   - the PKCS8/SEC1/PKCS1 key could not be loaded
    pub fn load_der(der: &[u8]) -> Result<Self, LoadError> {
        // Let's try evey known DER format one after the other
        if pkcs8::EncryptedPrivateKeyInfo::from_der(der).is_ok() {
            return Err(LoadError::Encrypted);
        }

        if let Ok(info) = pkcs8::PrivateKeyInfo::from_der(der) {
            return Self::from_private_key_info(info);
        }

        if let Ok(info) = sec1::EcPrivateKey::from_der(der) {
            return Self::from_ec_private_key(info);
        }

        if let Ok(pkcs1_key) = pkcs1::RsaPrivateKey::from_der(der) {
            return Self::from_pkcs1_private_key(&pkcs1_key);
        }

        Err(LoadError::UnsupportedFormat)
    }

    /// Load an encrypted key from a PEM-encode string, and decrypt it with the
    /// given password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the file is not a signel PEM document
    ///   - the PEM label is not a supported format
    ///   - the underlying key is not encrypted (use [`Self::load`] instead)
    ///   - the decryption failed
    ///   - the pkcs8 key could not be loaded
    pub fn load_encrypted_pem(pem: &str, password: impl AsRef<[u8]>) -> Result<Self, LoadError> {
        let (label, doc) = pem_rfc7468::decode_vec(pem.as_bytes())?;

        match label {
            pkcs8::EncryptedPrivateKeyInfo::PEM_LABEL => {
                let info = pkcs8::EncryptedPrivateKeyInfo::from_der(&doc)?;
                let decrypted = info.decrypt(password)?;
                return Self::load_der(decrypted.as_bytes()).map_err(|inner| {
                    LoadError::InEncrypted {
                        inner: Box::new(inner),
                    }
                });
            }

            pkcs1::RsaPrivateKey::PEM_LABEL
            | pkcs8::PrivateKeyInfo::PEM_LABEL
            | sec1::EcPrivateKey::PEM_LABEL => Err(LoadError::Unencrypted),

            label => Err(LoadError::UnsupportedPemLabel {
                label: label.to_owned(),
            }),
        }
    }

    /// Load an unencrypted key from a PEM-encode string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the file is not a signel PEM document
    ///   - the PEM label is not a supported format
    ///   - the underlying key is encrypted (use [`Self::load_encrypted`]
    ///     instead)
    ///   - the PKCS8/PKCS1/SEC1 key could not be loaded
    pub fn load_pem(pem: &str) -> Result<Self, LoadError> {
        let (label, doc) = pem_rfc7468::decode_vec(pem.as_bytes())?;

        match label {
            pkcs1::RsaPrivateKey::PEM_LABEL => {
                let pkcs1_key = pkcs1::RsaPrivateKey::from_der(&doc)?;
                Self::from_pkcs1_private_key(&pkcs1_key)
            }

            pkcs8::PrivateKeyInfo::PEM_LABEL => {
                let info = pkcs8::PrivateKeyInfo::from_der(&doc)?;
                Self::from_private_key_info(info)
            }

            sec1::EcPrivateKey::PEM_LABEL => {
                let key = sec1::EcPrivateKey::from_der(&doc)?;
                Self::from_ec_private_key(key)
            }

            pkcs8::EncryptedPrivateKeyInfo::PEM_LABEL => Err(LoadError::Encrypted),

            label => Err(LoadError::UnsupportedPemLabel {
                label: label.to_owned(),
            }),
        }
    }

    /// Get an [`AsymmetricVerifyingKey`] out of this key, for the specified
    /// [`JsonWebSignatureAlg`]
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not suited for the selected algorithm
    pub fn verifying_key_for_alg(
        &self,
        alg: JsonWebSignatureAlg,
    ) -> Result<AsymmetricVerifyingKey, WrongAlgorithmError> {
        let key = match (self, alg) {
            (Self::Rsa(key), _) => {
                let key: rsa::RsaPublicKey = key.to_public_key();
                match alg {
                    JsonWebSignatureAlg::Rs256 => AsymmetricVerifyingKey::Rs256(key.into()),
                    JsonWebSignatureAlg::Rs384 => AsymmetricVerifyingKey::Rs384(key.into()),
                    JsonWebSignatureAlg::Rs512 => AsymmetricVerifyingKey::Rs512(key.into()),
                    JsonWebSignatureAlg::Ps256 => AsymmetricVerifyingKey::Ps256(key.into()),
                    JsonWebSignatureAlg::Ps384 => AsymmetricVerifyingKey::Ps384(key.into()),
                    JsonWebSignatureAlg::Ps512 => AsymmetricVerifyingKey::Ps512(key.into()),
                    _ => return Err(WrongAlgorithmError),
                }
            }

            (Self::EcP256(key), JsonWebSignatureAlg::Es256) => {
                AsymmetricVerifyingKey::Es256(key.public_key().into())
            }

            (Self::EcP384(key), JsonWebSignatureAlg::Es384) => {
                AsymmetricVerifyingKey::Es384(key.public_key().into())
            }

            (Self::EcK256(key), JsonWebSignatureAlg::Es256K) => {
                AsymmetricVerifyingKey::Es256K(key.public_key().into())
            }

            _ => return Err(WrongAlgorithmError),
        };

        Ok(key)
    }

    /// Get a [`AsymmetricSigningKey`] out of this key, for the specified
    /// [`JsonWebSignatureAlg`]
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not suited for the selected algorithm
    pub fn signing_key_for_alg(
        &self,
        alg: JsonWebSignatureAlg,
    ) -> Result<AsymmetricSigningKey, WrongAlgorithmError> {
        let key = match (self, alg) {
            (Self::Rsa(key), _) => {
                let key: rsa::RsaPrivateKey = *key.clone();
                match alg {
                    JsonWebSignatureAlg::Rs256 => AsymmetricSigningKey::Rs256(key.into()),
                    JsonWebSignatureAlg::Rs384 => AsymmetricSigningKey::Rs384(key.into()),
                    JsonWebSignatureAlg::Rs512 => AsymmetricSigningKey::Rs512(key.into()),
                    JsonWebSignatureAlg::Ps256 => AsymmetricSigningKey::Ps256(key.into()),
                    JsonWebSignatureAlg::Ps384 => AsymmetricSigningKey::Ps384(key.into()),
                    JsonWebSignatureAlg::Ps512 => AsymmetricSigningKey::Ps512(key.into()),
                    _ => return Err(WrongAlgorithmError),
                }
            }

            (Self::EcP256(key), JsonWebSignatureAlg::Es256) => {
                AsymmetricSigningKey::Es256(key.as_ref().into())
            }

            (Self::EcP384(key), JsonWebSignatureAlg::Es384) => {
                AsymmetricSigningKey::Es384(key.as_ref().into())
            }

            (Self::EcK256(key), JsonWebSignatureAlg::Es256K) => {
                AsymmetricSigningKey::Es256K(key.as_ref().into())
            }

            _ => return Err(WrongAlgorithmError),
        };

        Ok(key)
    }

    /// Generate a RSA key with 2048 bit size
    ///
    /// # Errors
    ///
    /// Returns any error from the underlying key generator
    pub fn generate_rsa<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, rsa::errors::Error> {
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
        Ok(Self::Rsa(Box::new(key)))
    }

    /// Generate an Elliptic Curve key for the P-256 curve
    pub fn generate_ec_p256<R: RngCore + CryptoRng>(rng: R) -> Self {
        let key = elliptic_curve::SecretKey::random(rng);
        Self::EcP256(Box::new(key))
    }

    /// Generate an Elliptic Curve key for the P-384 curve
    pub fn generate_ec_p384<R: RngCore + CryptoRng>(rng: R) -> Self {
        let key = elliptic_curve::SecretKey::random(rng);
        Self::EcP384(Box::new(key))
    }

    /// Generate an Elliptic Curve key for the secp256k1 curve
    pub fn generate_ec_k256<R: RngCore + CryptoRng>(rng: R) -> Self {
        let key = elliptic_curve::SecretKey::random(rng);
        Self::EcK256(Box::new(key))
    }
}

impl From<&PrivateKey> for JsonWebKeyPublicParameters {
    fn from(val: &PrivateKey) -> Self {
        match val {
            PrivateKey::Rsa(key) => key.to_public_key().into(),
            PrivateKey::EcP256(key) => {
                let key: ecdsa::VerifyingKey<_> = key.public_key().into();
                key.into()
            }
            PrivateKey::EcP384(key) => {
                let key: ecdsa::VerifyingKey<_> = key.public_key().into();
                key.into()
            }
            PrivateKey::EcK256(key) => {
                let key: ecdsa::VerifyingKey<_> = key.public_key().into();
                key.into()
            }
        }
    }
}

impl ParametersInfo for PrivateKey {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            PrivateKey::Rsa(_) => JsonWebKeyType::Rsa,
            PrivateKey::EcP256(_) | PrivateKey::EcP384(_) | PrivateKey::EcK256(_) => {
                JsonWebKeyType::Ec
            }
        }
    }

    fn possible_algs(&self) -> &'static [JsonWebSignatureAlg] {
        match self {
            PrivateKey::Rsa(_) => &[
                JsonWebSignatureAlg::Rs256,
                JsonWebSignatureAlg::Rs384,
                JsonWebSignatureAlg::Rs512,
                JsonWebSignatureAlg::Ps256,
                JsonWebSignatureAlg::Ps384,
                JsonWebSignatureAlg::Ps512,
            ],
            PrivateKey::EcP256(_) => &[JsonWebSignatureAlg::Es256],
            PrivateKey::EcP384(_) => &[JsonWebSignatureAlg::Es384],
            PrivateKey::EcK256(_) => &[JsonWebSignatureAlg::Es256K],
        }
    }
}

/// A structure to store a list of [`PrivateKey`]. The keys are held in an
/// [`Arc`] to ensure they are only loaded once in memory and allow cheap
/// cloning
#[derive(Clone, Default)]
pub struct Keystore {
    keys: Arc<JsonWebKeySet<PrivateKey>>,
}

impl Keystore {
    /// Create a keystore out of a JSON Web Key Set
    ///
    /// ```rust
    /// use mas_keystore::{Keystore, PrivateKey, JsonWebKey, JsonWebKeySet};
    /// let rsa = PrivateKey::load_pem(include_str!("../tests/keys/rsa.pkcs1.pem")).unwrap();
    /// let rsa = JsonWebKey::new(rsa);
    ///
    /// let ec_p256 = PrivateKey::load_pem(include_str!("../tests/keys/ec-p256.sec1.pem")).unwrap();
    /// let ec_p256 = JsonWebKey::new(ec_p256);
    ///
    /// let ec_p384 = PrivateKey::load_pem(include_str!("../tests/keys/ec-p384.sec1.pem")).unwrap();
    /// let ec_p384 = JsonWebKey::new(ec_p384);
    ///
    /// let ec_k256 = PrivateKey::load_pem(include_str!("../tests/keys/ec-k256.sec1.pem")).unwrap();
    /// let ec_k256 = JsonWebKey::new(ec_k256);
    ///
    /// let jwks = JsonWebKeySet::new(vec![rsa, ec_p256, ec_p384, ec_k256]);
    /// let keystore = Keystore::new(jwks);
    /// ```
    #[must_use]
    pub fn new(keys: JsonWebKeySet<PrivateKey>) -> Self {
        let keys = Arc::new(keys);
        Self { keys }
    }

    /// Get the public JSON Web Key Set for the keys stored in this [`Keystore`]
    #[must_use]
    pub fn public_jwks(&self) -> PublicJsonWebKeySet {
        self.keys
            .iter()
            .map(|key| {
                key.cloned_map(|params: &PrivateKey| JsonWebKeyPublicParameters::from(params))
            })
            .collect()
    }
}

impl Deref for Keystore {
    type Target = JsonWebKeySet<PrivateKey>;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}
