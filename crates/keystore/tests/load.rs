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

use mas_jose::{
    jwk::ParametersInfo,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::PrivateKey;

static PASSWORD: &str = "hunter2";

macro_rules! load_test {
    ($name:ident, $kind:ident, $path:literal) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!($path);
            let key = PrivateKey::load(bytes).unwrap();
            assert!(matches!(key, PrivateKey::$kind(_)), "wrong key type");
        }
    };
}

macro_rules! load_encrypted_test {
    ($name:ident, $kind:ident, $path:literal) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!($path);
            let key = PrivateKey::load_encrypted(bytes, PASSWORD).unwrap();
            assert!(matches!(key, PrivateKey::$kind(_)), "wrong key type");

            let algs = key.possible_algs();
            assert_ne!(algs.len(), 0);

            for &alg in algs {
                let header = JsonWebSignatureHeader::new(alg);
                let payload = "hello";
                let signer = key.signer_for_alg(alg).unwrap();
                let jwt = Jwt::sign(header, payload, &signer).unwrap();
                let verifier = key.verifier_for_alg(alg).unwrap();
                jwt.verify(&verifier).unwrap();
            }
        }
    };
}

load_test!(load_rsa_pkcs1_pem, Rsa, "./keys/rsa.pkcs1.pem");
load_test!(load_rsa_pkcs1_der, Rsa, "./keys/rsa.pkcs1.der");
load_test!(load_rsa_pkcs8_pem, Rsa, "./keys/rsa.pkcs8.pem");
load_test!(load_rsa_pkcs8_der, Rsa, "./keys/rsa.pkcs8.der");
load_test!(load_ec_p256_sec1_pem, EcP256, "./keys/ec-p256.sec1.pem");
load_test!(load_ec_p256_sec1_der, EcP256, "./keys/ec-p256.sec1.der");
load_test!(load_ec_p256_pkcs8_pem, EcP256, "./keys/ec-p256.pkcs8.pem");
load_test!(load_ec_p256_pkcs8_der, EcP256, "./keys/ec-p256.pkcs8.der");
load_test!(load_ec_p384_sec1_pem, EcP384, "./keys/ec-p384.sec1.pem");
load_test!(load_ec_p384_sec1_der, EcP384, "./keys/ec-p384.sec1.der");
load_test!(load_ec_p384_pkcs8_pem, EcP384, "./keys/ec-p384.pkcs8.pem");
load_test!(load_ec_p384_pkcs8_der, EcP384, "./keys/ec-p384.pkcs8.der");
load_test!(load_ec_k256_sec1_pem, EcK256, "./keys/ec-k256.sec1.pem");
load_test!(load_ec_k256_sec1_der, EcK256, "./keys/ec-k256.sec1.der");
load_test!(load_ec_k256_pkcs8_pem, EcK256, "./keys/ec-k256.pkcs8.pem");
load_test!(load_ec_k256_pkcs8_der, EcK256, "./keys/ec-k256.pkcs8.der");

load_encrypted_test!(
    load_encrypted_rsa_pkcs8_pem,
    Rsa,
    "./keys/rsa.pkcs8.encrypted.pem"
);
load_encrypted_test!(
    load_encrypted_rsa_pkcs8_der,
    Rsa,
    "./keys/rsa.pkcs8.encrypted.der"
);
load_encrypted_test!(
    load_encrypted_ec_p256_pkcs8_pem,
    EcP256,
    "./keys/ec-p256.pkcs8.encrypted.pem"
);
load_encrypted_test!(
    load_encrypted_ec_p256_pkcs8_der,
    EcP256,
    "./keys/ec-p256.pkcs8.encrypted.der"
);
load_encrypted_test!(
    load_encrypted_ec_p384_pkcs8_pem,
    EcP384,
    "./keys/ec-p384.pkcs8.encrypted.pem"
);
load_encrypted_test!(
    load_encrypted_ec_p384_pkcs8_der,
    EcP384,
    "./keys/ec-p384.pkcs8.encrypted.der"
);
load_encrypted_test!(
    load_encrypted_ec_k256_pkcs8_pem,
    EcK256,
    "./keys/ec-k256.pkcs8.encrypted.pem"
);
load_encrypted_test!(
    load_encrypted_ec_k256_pkcs8_der,
    EcK256,
    "./keys/ec-k256.pkcs8.encrypted.der"
);
