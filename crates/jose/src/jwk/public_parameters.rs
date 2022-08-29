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

use mas_iana::jose::{JsonWebKeyEcEllipticCurve, JsonWebKeyOkpEllipticCurve, JsonWebKeyType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};

use super::JwkKty;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kty")]
pub enum JsonWebKeyPublicParameters {
    #[serde(rename = "RSA")]
    Rsa(RsaPublicParameters),

    #[serde(rename = "EC")]
    Ec(EcPublicParameters),

    #[serde(rename = "OKP")]
    Okp(OkpPublicParameters),
}

impl JwkKty for JsonWebKeyPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsaPublicParameters {
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    n: Vec<u8>,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    e: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EcPublicParameters {
    pub(crate) crv: JsonWebKeyEcEllipticCurve,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    x: Vec<u8>,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    y: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OkpPublicParameters {
    crv: JsonWebKeyOkpEllipticCurve,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    x: Vec<u8>,
}

impl EcPublicParameters {
    pub const fn crv(&self) -> JsonWebKeyEcEllipticCurve {
        self.crv
    }
}

mod rsa_impls {
    use rsa::{BigUint, RsaPublicKey};

    use super::RsaPublicParameters;

    impl TryFrom<RsaPublicParameters> for RsaPublicKey {
        type Error = rsa::errors::Error;
        fn try_from(value: RsaPublicParameters) -> Result<Self, Self::Error> {
            (&value).try_into()
        }
    }

    impl TryFrom<&RsaPublicParameters> for RsaPublicKey {
        type Error = rsa::errors::Error;
        fn try_from(value: &RsaPublicParameters) -> Result<Self, Self::Error> {
            let n = BigUint::from_bytes_be(&value.n);
            let e = BigUint::from_bytes_be(&value.e);
            let key = RsaPublicKey::new(n, e)?;
            Ok(key)
        }
    }
}

mod ec_impls {
    use digest::typenum::Unsigned;
    use ecdsa::{EncodedPoint, PrimeCurve, VerifyingKey};
    use elliptic_curve::{
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
        AffinePoint, Curve, FieldBytes, FieldSize, ProjectiveArithmetic, PublicKey,
    };

    use super::{super::JwkEcCurve, EcPublicParameters};

    impl<C> TryFrom<EcPublicParameters> for VerifyingKey<C>
    where
        C: PrimeCurve + ProjectiveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        type Error = ecdsa::Error;
        fn try_from(value: EcPublicParameters) -> Result<Self, Self::Error> {
            (&value).try_into()
        }
    }

    impl<C> TryFrom<&EcPublicParameters> for VerifyingKey<C>
    where
        C: PrimeCurve + ProjectiveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        type Error = ecdsa::Error;

        fn try_from(value: &EcPublicParameters) -> Result<Self, Self::Error> {
            if value.crv() != C::CRV {
                return Err(Self::Error::default());
            }

            let x = value
                .x
                .get(..FieldSize::<C>::USIZE)
                .ok_or_else(Self::Error::default)?;
            let y = value
                .x
                .get(..FieldSize::<C>::USIZE)
                .ok_or_else(Self::Error::default)?;

            let x = FieldBytes::<C>::from_slice(x);
            let y = FieldBytes::<C>::from_slice(y);
            let pubkey = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let pubkey = VerifyingKey::from_encoded_point(&pubkey)?;
            Ok(pubkey)
        }
    }

    impl<C> From<PublicKey<C>> for EcPublicParameters
    where
        C: Curve + elliptic_curve::ProjectiveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&PublicKey<C>> for EcPublicParameters
    where
        C: Curve + elliptic_curve::ProjectiveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            let point = key.to_encoded_point(false);
            let (x, y) = match point.coordinates() {
                Coordinates::Uncompressed { x, y } => (x, y),
                _ => unreachable!(),
            };
            EcPublicParameters {
                crv: C::CRV,
                x: x.to_vec(),
                y: y.to_vec(),
            }
        }
    }
}

/// Some legacy implementations to remove
mod legacy {
    use anyhow::bail;
    use mas_iana::jose::JsonWebKeyEcEllipticCurve;
    use p256::NistP256;
    use rsa::{BigUint, PublicKeyParts};

    use super::{EcPublicParameters, JsonWebKeyPublicParameters, RsaPublicParameters};

    impl TryFrom<JsonWebKeyPublicParameters> for ecdsa::VerifyingKey<NistP256> {
        type Error = anyhow::Error;

        fn try_from(params: JsonWebKeyPublicParameters) -> Result<Self, Self::Error> {
            let (x, y): ([u8; 32], [u8; 32]) = match params {
                JsonWebKeyPublicParameters::Ec(EcPublicParameters {
                    x,
                    y,
                    crv: JsonWebKeyEcEllipticCurve::P256,
                }) => (
                    x.try_into()
                        .map_err(|_| anyhow::anyhow!("invalid curve parameter x"))?,
                    y.try_into()
                        .map_err(|_| anyhow::anyhow!("invalid curve parameter y"))?,
                ),
                _ => bail!("Wrong key type"),
            };

            let point = sec1::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
            let key = ecdsa::VerifyingKey::from_encoded_point(&point)?;
            Ok(key)
        }
    }

    impl From<ecdsa::VerifyingKey<NistP256>> for JsonWebKeyPublicParameters {
        fn from(key: ecdsa::VerifyingKey<NistP256>) -> Self {
            let points = key.to_encoded_point(false);
            JsonWebKeyPublicParameters::Ec(EcPublicParameters {
                x: points.x().unwrap().to_vec(),
                y: points.y().unwrap().to_vec(),
                crv: JsonWebKeyEcEllipticCurve::P256,
            })
        }
    }

    impl TryFrom<JsonWebKeyPublicParameters> for rsa::RsaPublicKey {
        type Error = anyhow::Error;

        fn try_from(params: JsonWebKeyPublicParameters) -> Result<Self, Self::Error> {
            let (n, e) = match &params {
                JsonWebKeyPublicParameters::Rsa(RsaPublicParameters { n, e }) => (n, e),
                _ => bail!("Wrong key type"),
            };
            let n = BigUint::from_bytes_be(n);
            let e = BigUint::from_bytes_be(e);
            Ok(rsa::RsaPublicKey::new(n, e)?)
        }
    }

    impl From<rsa::RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: rsa::RsaPublicKey) -> Self {
            JsonWebKeyPublicParameters::Rsa(RsaPublicParameters {
                n: key.n().to_bytes_be(),
                e: key.e().to_bytes_be(),
            })
        }
    }
}
