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

use std::ops::Deref;

use mas_jose::{constraints::ConstraintSet, JsonWebKeySet, Jwt};
use serde::Deserialize;

static HS256_JWT: &str = include_str!("./jwts/hs256.jwt");
static HS384_JWT: &str = include_str!("./jwts/hs384.jwt");
static HS512_JWT: &str = include_str!("./jwts/hs512.jwt");
static RS256_JWT: &str = include_str!("./jwts/rs256.jwt");
static RS384_JWT: &str = include_str!("./jwts/rs384.jwt");
static RS512_JWT: &str = include_str!("./jwts/rs512.jwt");
static PS256_JWT: &str = include_str!("./jwts/ps256.jwt");
static PS384_JWT: &str = include_str!("./jwts/ps384.jwt");
static PS512_JWT: &str = include_str!("./jwts/ps512.jwt");
static ES256_JWT: &str = include_str!("./jwts/es256.jwt");
static ES384_JWT: &str = include_str!("./jwts/es384.jwt");
static ES512_JWT: &str = include_str!("./jwts/es512.jwt");
static ES256K_JWT: &str = include_str!("./jwts/es256k.jwt");
static EDDSA_ED25519_JWT: &str = include_str!("./jwts/eddsa-ed25519.jwt");
static EDDSA_ED448_JWT: &str = include_str!("./jwts/eddsa-ed448.jwt");
static OCT_KEY: &[u8] = include_bytes!("./keys/oct.bin");

fn public_jwks() -> JsonWebKeySet {
    serde_json::from_str(include_str!("./keys/jwks.pub.json")).unwrap()
}

fn oct_key() -> Vec<u8> {
    OCT_KEY.to_vec()
}

#[derive(Deserialize)]
struct Payload {
    hello: String,
}

macro_rules! asymetric_jwt_test {
    ($test_name:ident, $jwt:ident) => {
        asymetric_jwt_test!($test_name, $jwt, verify = true);
    };
    ($test_name:ident, $jwt:ident, verify = $verify:ident) => {
        #[test]
        fn $test_name() {
            let jwks = public_jwks();
            let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
            assert_eq!(jwt.payload().hello, "world");

            let constraints = ConstraintSet::from(jwt.header());
            let candidates = constraints.filter(jwks.deref());
            assert_eq!(candidates.len(), 1);
            let candidate = candidates[0];

            if $verify {
                let verifier = mas_jose::verifier::Verifier::for_jwk_and_alg(
                    candidate.params(),
                    jwt.header().alg(),
                )
                .unwrap();
                jwt.verify(&verifier).unwrap();
            }
        }
    };
}

macro_rules! symetric_jwt_test {
    ($test_name:ident, $jwt:ident) => {
        #[test]
        fn $test_name() {
            let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
            let verifier =
                mas_jose::verifier::Verifier::for_oct_and_alg(oct_key(), jwt.header().alg())
                    .unwrap();
            assert_eq!(jwt.payload().hello, "world");
            jwt.verify(&verifier).unwrap();
        }
    };
}

symetric_jwt_test!(test_hs256, HS256_JWT);
symetric_jwt_test!(test_hs384, HS384_JWT);
symetric_jwt_test!(test_hs512, HS512_JWT);

asymetric_jwt_test!(test_rs256, RS256_JWT);
asymetric_jwt_test!(test_rs384, RS384_JWT);
asymetric_jwt_test!(test_rs512, RS512_JWT);
asymetric_jwt_test!(test_ps256, PS256_JWT);
asymetric_jwt_test!(test_ps384, PS384_JWT);
asymetric_jwt_test!(test_ps512, PS512_JWT);
asymetric_jwt_test!(test_es256, ES256_JWT);
asymetric_jwt_test!(test_es384, ES384_JWT);
asymetric_jwt_test!(test_es512, ES512_JWT, verify = false);
asymetric_jwt_test!(test_es256k, ES256K_JWT);
asymetric_jwt_test!(test_eddsa_ed25519, EDDSA_ED25519_JWT, verify = false);
asymetric_jwt_test!(test_eddsa_ed448, EDDSA_ED448_JWT, verify = false);
