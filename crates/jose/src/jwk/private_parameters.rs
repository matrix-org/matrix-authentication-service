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

impl JwkKty for JsonWebKeyPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Oct(_) => JsonWebKeyType::Oct,
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
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
    use rsa::{BigUint, RsaPrivateKey};

    use super::RsaPrivateParameters;

    impl TryInto<RsaPrivateKey> for RsaPrivateParameters {
        type Error = rsa::errors::Error;
        fn try_into(self) -> Result<RsaPrivateKey, Self::Error> {
            (&self).try_into()
        }
    }

    impl TryInto<RsaPrivateKey> for &RsaPrivateParameters {
        type Error = rsa::errors::Error;

        #[allow(clippy::many_single_char_names)]
        fn try_into(self) -> Result<RsaPrivateKey, Self::Error> {
            let n = BigUint::from_bytes_be(&self.n);
            let e = BigUint::from_bytes_be(&self.e);
            let d = BigUint::from_bytes_be(&self.d);

            let primes = [&self.p, &self.q]
                .into_iter()
                .chain(self.oth.iter().flatten().map(|o| &o.r))
                .map(|i| BigUint::from_bytes_be(i))
                .collect();

            RsaPrivateKey::from_components(n, e, d, primes)
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EcPrivateParameters {
    crv: JsonWebKeyEcEllipticCurve,

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

mod ec_impls {
    use digest::typenum::Unsigned;
    use ecdsa::EncodedPoint;
    use elliptic_curve::{
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
        AffinePoint, Curve, FieldBytes, FieldSize, SecretKey,
    };

    use super::{super::JwkEcCurve, EcPrivateParameters};

    impl<C> TryInto<SecretKey<C>> for EcPrivateParameters
    where
        C: Curve + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        type Error = elliptic_curve::Error;
        fn try_into(self) -> Result<SecretKey<C>, Self::Error> {
            (&self).try_into()
        }
    }

    impl<C> TryInto<SecretKey<C>> for &EcPrivateParameters
    where
        C: Curve + ValidatePublicKey,
        FieldSize<C>: ModulusSize,
    {
        type Error = elliptic_curve::Error;

        fn try_into(self) -> Result<SecretKey<C>, Self::Error> {
            let x = self
                .x
                .get(..FieldSize::<C>::USIZE)
                .ok_or(elliptic_curve::Error)?;
            let y = self
                .x
                .get(..FieldSize::<C>::USIZE)
                .ok_or(elliptic_curve::Error)?;

            let x = FieldBytes::<C>::from_slice(x);
            let y = FieldBytes::<C>::from_slice(y);
            let pubkey = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let privkey = SecretKey::from_be_bytes(&self.d)?;
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
