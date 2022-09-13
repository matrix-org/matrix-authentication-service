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
use thiserror::Error;

use super::{public_parameters::JsonWebKeyPublicParameters, ParametersInfo};

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kty")]
pub enum JsonWebKeyPrivateParameters {
    #[serde(rename = "oct")]
    Oct(OctPrivateParameters),

    #[serde(rename = "RSA")]
    Rsa(RsaPrivateParameters),

    #[serde(rename = "EC")]
    Ec(EcPrivateParameters),

    #[serde(rename = "OKP")]
    Okp(OkpPrivateParameters),
}

impl JsonWebKeyPrivateParameters {
    #[must_use]
    pub const fn oct(&self) -> Option<&OctPrivateParameters> {
        match self {
            Self::Oct(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn rsa(&self) -> Option<&RsaPrivateParameters> {
        match self {
            Self::Rsa(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn ec(&self) -> Option<&EcPrivateParameters> {
        match self {
            Self::Ec(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn okp(&self) -> Option<&OkpPrivateParameters> {
        match self {
            Self::Okp(params) => Some(params),
            _ => None,
        }
    }
}

impl ParametersInfo for JsonWebKeyPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Oct(_) => JsonWebKeyType::Oct,
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
        }
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self {
            JsonWebKeyPrivateParameters::Oct(p) => p.possible_algs(),
            JsonWebKeyPrivateParameters::Rsa(p) => p.possible_algs(),
            JsonWebKeyPrivateParameters::Ec(p) => p.possible_algs(),
            JsonWebKeyPrivateParameters::Okp(p) => p.possible_algs(),
        }
    }
}

#[derive(Debug, Error)]
#[error("can't extract a public key out of a symetric key")]
pub struct SymetricKeyError;

impl TryFrom<JsonWebKeyPrivateParameters> for JsonWebKeyPublicParameters {
    type Error = SymetricKeyError;

    fn try_from(value: JsonWebKeyPrivateParameters) -> Result<Self, Self::Error> {
        match value {
            JsonWebKeyPrivateParameters::Oct(_) => Err(SymetricKeyError),
            JsonWebKeyPrivateParameters::Rsa(p) => Ok(JsonWebKeyPublicParameters::Rsa(p.into())),
            JsonWebKeyPrivateParameters::Ec(p) => Ok(JsonWebKeyPublicParameters::Ec(p.into())),
            JsonWebKeyPrivateParameters::Okp(p) => Ok(JsonWebKeyPublicParameters::Okp(p.into())),
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OctPrivateParameters {
    /// Key Value
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    k: Vec<u8>,
}

impl ParametersInfo for OctPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Oct
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[
            JsonWebSignatureAlg::Hs256,
            JsonWebSignatureAlg::Hs384,
            JsonWebSignatureAlg::Hs512,
        ]
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsaPrivateParameters {
    /// Modulus
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    n: Vec<u8>,

    /// Exponent
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    e: Vec<u8>,

    /// Private Exponent
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    d: Vec<u8>,

    /// First Prime Factor
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    p: Vec<u8>,

    /// Second Prime Factor
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    q: Vec<u8>,

    /// First Factor CRT Exponent
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    dp: Vec<u8>,

    /// Second Factor CRT Exponent
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    dq: Vec<u8>,

    /// First CRT Coefficient
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    qi: Vec<u8>,

    /// Other Primes Info
    #[serde(skip_serializing_if = "Option::is_none")]
    oth: Option<Vec<RsaOtherPrimeInfo>>,
}

impl ParametersInfo for RsaPrivateParameters {
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

impl From<RsaPrivateParameters> for super::public_parameters::RsaPublicParameters {
    fn from(params: RsaPrivateParameters) -> Self {
        Self::new(params.n, params.e)
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct RsaOtherPrimeInfo {
    /// Prime Factor
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    r: Vec<u8>,

    /// Factor CRT Exponent
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    d: Vec<u8>,

    /// Factor CRT Coefficient
    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    t: Vec<u8>,
}

mod rsa_impls {
    use digest::{const_oid::AssociatedOid, Digest};
    use rsa::{BigUint, RsaPrivateKey};

    use super::RsaPrivateParameters;

    impl<H> TryFrom<RsaPrivateParameters> for rsa::pkcs1v15::SigningKey<H>
    where
        H: Digest + AssociatedOid,
    {
        type Error = rsa::errors::Error;
        fn try_from(value: RsaPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl<H> TryFrom<&RsaPrivateParameters> for rsa::pkcs1v15::SigningKey<H>
    where
        H: Digest + AssociatedOid,
    {
        type Error = rsa::errors::Error;
        fn try_from(value: &RsaPrivateParameters) -> Result<Self, Self::Error> {
            let key: RsaPrivateKey = value.try_into()?;
            Ok(Self::new_with_prefix(key))
        }
    }

    impl<H> TryFrom<RsaPrivateParameters> for rsa::pss::SigningKey<H>
    where
        H: Digest,
    {
        type Error = rsa::errors::Error;
        fn try_from(value: RsaPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl<H> TryFrom<&RsaPrivateParameters> for rsa::pss::SigningKey<H>
    where
        H: Digest,
    {
        type Error = rsa::errors::Error;
        fn try_from(value: &RsaPrivateParameters) -> Result<Self, Self::Error> {
            let key: RsaPrivateKey = value.try_into()?;
            Ok(Self::new(key))
        }
    }

    impl TryFrom<RsaPrivateParameters> for RsaPrivateKey {
        type Error = rsa::errors::Error;
        fn try_from(value: RsaPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl TryFrom<&RsaPrivateParameters> for RsaPrivateKey {
        type Error = rsa::errors::Error;

        #[allow(clippy::many_single_char_names)]
        fn try_from(value: &RsaPrivateParameters) -> Result<Self, Self::Error> {
            let n = BigUint::from_bytes_be(&value.n);
            let e = BigUint::from_bytes_be(&value.e);
            let d = BigUint::from_bytes_be(&value.d);

            let primes = [&value.p, &value.q]
                .into_iter()
                .chain(value.oth.iter().flatten().map(|o| &o.r))
                .map(|i| BigUint::from_bytes_be(i))
                .collect();

            let key = RsaPrivateKey::from_components(n, e, d, primes)?;

            key.validate()?;

            Ok(key)
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EcPrivateParameters {
    pub(crate) crv: JsonWebKeyEcEllipticCurve,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    x: Vec<u8>,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    y: Vec<u8>,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    d: Vec<u8>,
}

impl ParametersInfo for EcPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Ec
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self.crv {
            JsonWebKeyEcEllipticCurve::P256 => &[JsonWebSignatureAlg::Es256],
            JsonWebKeyEcEllipticCurve::P384 => &[JsonWebSignatureAlg::Es384],
            JsonWebKeyEcEllipticCurve::P521 => &[JsonWebSignatureAlg::Es512],
            JsonWebKeyEcEllipticCurve::Secp256K1 => &[JsonWebSignatureAlg::Es256K],
            _ => &[],
        }
    }
}

impl From<EcPrivateParameters> for super::public_parameters::EcPublicParameters {
    fn from(params: EcPrivateParameters) -> Self {
        Self::new(params.crv, params.x, params.y)
    }
}

mod ec_impls {
    use digest::typenum::Unsigned;
    use ecdsa::{hazmat::SignPrimitive, EncodedPoint, PrimeCurve, SignatureSize, SigningKey};
    use elliptic_curve::{
        ops::{Invert, Reduce},
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
        subtle::CtOption,
        AffinePoint, Curve, FieldBytes, FieldSize, ProjectiveArithmetic, Scalar, SecretKey,
    };
    use generic_array::ArrayLength;

    use super::{super::JwkEcCurve, EcPrivateParameters};

    impl<C> TryFrom<EcPrivateParameters> for SigningKey<C>
    where
        C: PrimeCurve + ProjectiveArithmetic,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
        SignatureSize<C>: ArrayLength<u8>,
    {
        type Error = ecdsa::Error;

        fn try_from(value: EcPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl<C> TryFrom<&EcPrivateParameters> for SigningKey<C>
    where
        C: PrimeCurve + ProjectiveArithmetic,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
        SignatureSize<C>: ArrayLength<u8>,
    {
        type Error = ecdsa::Error;

        fn try_from(value: &EcPrivateParameters) -> Result<Self, Self::Error> {
            SigningKey::from_bytes(&value.d)
        }
    }

    impl<C> TryFrom<EcPrivateParameters> for SecretKey<C>
    where
        C: Curve + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        type Error = elliptic_curve::Error;
        fn try_from(value: EcPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl<C> TryFrom<&EcPrivateParameters> for SecretKey<C>
    where
        C: Curve + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        type Error = elliptic_curve::Error;

        fn try_from(value: &EcPrivateParameters) -> Result<Self, Self::Error> {
            let x = value
                .x
                .get(..FieldSize::<C>::USIZE)
                .ok_or(elliptic_curve::Error)?;
            let y = value
                .x
                .get(..FieldSize::<C>::USIZE)
                .ok_or(elliptic_curve::Error)?;

            let x = FieldBytes::<C>::from_slice(x);
            let y = FieldBytes::<C>::from_slice(y);
            let pubkey = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let privkey = SecretKey::from_be_bytes(&value.d)?;
            C::validate_public_key(&privkey, &pubkey)?;
            Ok(privkey)
        }
    }

    impl<C> From<SecretKey<C>> for EcPrivateParameters
    where
        C: Curve + elliptic_curve::ProjectiveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        fn from(key: SecretKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&SecretKey<C>> for EcPrivateParameters
    where
        C: Curve + elliptic_curve::ProjectiveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldSize<C>: ModulusSize,
    {
        fn from(key: &SecretKey<C>) -> Self {
            let point = key.public_key().to_encoded_point(false);
            let (x, y) = match point.coordinates() {
                Coordinates::Uncompressed { x, y } => (x, y),
                _ => unreachable!(),
            };
            let d = key.to_be_bytes();
            EcPrivateParameters {
                crv: C::CRV,
                x: x.to_vec(),
                y: y.to_vec(),
                d: d.to_vec(),
            }
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OkpPrivateParameters {
    crv: JsonWebKeyOkpEllipticCurve,

    #[schemars(with = "String")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    x: Vec<u8>,
}

impl ParametersInfo for OkpPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Okp
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[JsonWebSignatureAlg::EdDsa]
    }
}

impl From<OkpPrivateParameters> for super::public_parameters::OkpPublicParameters {
    fn from(params: OkpPrivateParameters) -> Self {
        Self::new(params.crv, params.x)
    }
}
