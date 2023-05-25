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

use mas_iana::jose::{
    JsonWebKeyEcEllipticCurve, JsonWebKeyOkpEllipticCurve, JsonWebKeyType, JsonWebSignatureAlg,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};

use super::ParametersInfo;

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

impl JsonWebKeyPublicParameters {
    #[must_use]
    pub const fn rsa(&self) -> Option<&RsaPublicParameters> {
        match self {
            Self::Rsa(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn ec(&self) -> Option<&EcPublicParameters> {
        match self {
            Self::Ec(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn okp(&self) -> Option<&OkpPublicParameters> {
        match self {
            Self::Okp(params) => Some(params),
            _ => None,
        }
    }
}

impl ParametersInfo for JsonWebKeyPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
        }
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self {
            JsonWebKeyPublicParameters::Rsa(p) => p.possible_algs(),
            JsonWebKeyPublicParameters::Ec(p) => p.possible_algs(),
            JsonWebKeyPublicParameters::Okp(p) => p.possible_algs(),
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

impl ParametersInfo for RsaPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Rsa
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[
            JsonWebSignatureAlg::Rs256,
            JsonWebSignatureAlg::Rs384,
            JsonWebSignatureAlg::Rs512,
            JsonWebSignatureAlg::Ps256,
            JsonWebSignatureAlg::Ps384,
            JsonWebSignatureAlg::Ps512,
        ]
    }
}

impl RsaPublicParameters {
    pub const fn new(n: Vec<u8>, e: Vec<u8>) -> Self {
        Self { n, e }
    }
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

impl EcPublicParameters {
    pub const fn new(crv: JsonWebKeyEcEllipticCurve, x: Vec<u8>, y: Vec<u8>) -> Self {
        Self { crv, x, y }
    }
}

impl ParametersInfo for EcPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Ec
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match &self.crv {
            JsonWebKeyEcEllipticCurve::P256 => &[JsonWebSignatureAlg::Es256],
            JsonWebKeyEcEllipticCurve::P384 => &[JsonWebSignatureAlg::Es384],
            JsonWebKeyEcEllipticCurve::P521 => &[JsonWebSignatureAlg::Es512],
            JsonWebKeyEcEllipticCurve::Secp256K1 => &[JsonWebSignatureAlg::Es256K],
            _ => &[],
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OkpPublicParameters {
    crv: JsonWebKeyOkpEllipticCurve,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    x: Vec<u8>,
}

impl ParametersInfo for OkpPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Okp
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[JsonWebSignatureAlg::EdDsa]
    }
}

impl OkpPublicParameters {
    pub const fn new(crv: JsonWebKeyOkpEllipticCurve, x: Vec<u8>) -> Self {
        Self { crv, x }
    }
}

mod rsa_impls {
    use rsa::{traits::PublicKeyParts, BigUint, RsaPublicKey};

    use super::{JsonWebKeyPublicParameters, RsaPublicParameters};

    impl From<RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: RsaPublicKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: &RsaPublicKey) -> Self {
            Self::Rsa(key.into())
        }
    }

    impl From<RsaPublicKey> for RsaPublicParameters {
        fn from(key: RsaPublicKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&RsaPublicKey> for RsaPublicParameters {
        fn from(key: &RsaPublicKey) -> Self {
            Self {
                n: key.n().to_bytes_be(),
                e: key.e().to_bytes_be(),
            }
        }
    }

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
    use ecdsa::EncodedPoint;
    use elliptic_curve::{
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
        AffinePoint, FieldBytes, PublicKey,
    };

    use super::{super::JwkEcCurve, EcPublicParameters, JsonWebKeyPublicParameters};

    impl<C> TryFrom<&EcPublicParameters> for PublicKey<C>
    where
        C: elliptic_curve::CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize + Unsigned,
    {
        type Error = elliptic_curve::Error;
        fn try_from(value: &EcPublicParameters) -> Result<Self, Self::Error> {
            let x = value
                .x
                .get(..C::FieldBytesSize::USIZE)
                .ok_or(elliptic_curve::Error)?;
            let y = value
                .y
                .get(..C::FieldBytesSize::USIZE)
                .ok_or(elliptic_curve::Error)?;

            let x = FieldBytes::<C>::from_slice(x);
            let y = FieldBytes::<C>::from_slice(y);
            let pubkey = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let pubkey: Option<_> = PublicKey::from_encoded_point(&pubkey).into();
            pubkey.ok_or(elliptic_curve::Error)
        }
    }

    impl<C> From<PublicKey<C>> for JsonWebKeyPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&PublicKey<C>> for JsonWebKeyPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            Self::Ec(key.into())
        }
    }

    impl<C> From<PublicKey<C>> for EcPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&PublicKey<C>> for EcPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            let point = key.to_encoded_point(false);
            let Coordinates::Uncompressed { x, y } = point.coordinates() else {
                unreachable!()
            };
            EcPublicParameters {
                crv: C::CRV,
                x: x.to_vec(),
                y: y.to_vec(),
            }
        }
    }
}
