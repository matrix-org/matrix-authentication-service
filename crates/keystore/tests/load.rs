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

macro_rules! plain_test {
    ($name:ident, $kind:ident, $path:literal) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!(concat!("./keys/", $path));
            let key = PrivateKey::load(bytes).unwrap();
            assert!(matches!(key, PrivateKey::$kind(_)), "wrong key type");
        }
    };
}

macro_rules! enc_test {
    ($name:ident, $kind:ident, $path:literal) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!(concat!("./keys/", $path));
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

plain_test!(plain_rsa_pkcs1_pem, Rsa, "rsa.pkcs1.pem");
plain_test!(plain_rsa_pkcs1_der, Rsa, "rsa.pkcs1.der");
plain_test!(plain_rsa_pkcs8_pem, Rsa, "rsa.pkcs8.pem");
plain_test!(plain_rsa_pkcs8_der, Rsa, "rsa.pkcs8.der");
plain_test!(plain_ec_p256_sec1_pem, EcP256, "ec-p256.sec1.pem");
plain_test!(plain_ec_p256_sec1_der, EcP256, "ec-p256.sec1.der");
plain_test!(plain_ec_p256_pkcs8_pem, EcP256, "ec-p256.pkcs8.pem");
plain_test!(plain_ec_p256_pkcs8_der, EcP256, "ec-p256.pkcs8.der");
plain_test!(plain_ec_p384_sec1_pem, EcP384, "ec-p384.sec1.pem");
plain_test!(plain_ec_p384_sec1_der, EcP384, "ec-p384.sec1.der");
plain_test!(plain_ec_p384_pkcs8_pem, EcP384, "ec-p384.pkcs8.pem");
plain_test!(plain_ec_p384_pkcs8_der, EcP384, "ec-p384.pkcs8.der");
plain_test!(plain_ec_k256_sec1_pem, EcK256, "ec-k256.sec1.pem");
plain_test!(plain_ec_k256_sec1_der, EcK256, "ec-k256.sec1.der");
plain_test!(plain_ec_k256_pkcs8_pem, EcK256, "ec-k256.pkcs8.pem");
plain_test!(plain_ec_k256_pkcs8_der, EcK256, "ec-k256.pkcs8.der");

enc_test!(enc_rsa_pkcs8_pem, Rsa, "rsa.pkcs8.encrypted.pem");
enc_test!(enc_rsa_pkcs8_der, Rsa, "rsa.pkcs8.encrypted.der");
enc_test!(enc_ec_p256_pkcs8_pem, EcP256, "ec-p256.pkcs8.encrypted.pem");
enc_test!(enc_ec_p256_pkcs8_der, EcP256, "ec-p256.pkcs8.encrypted.der");
enc_test!(enc_ec_p384_pkcs8_pem, EcP384, "ec-p384.pkcs8.encrypted.pem");
enc_test!(enc_ec_p384_pkcs8_der, EcP384, "ec-p384.pkcs8.encrypted.der");
enc_test!(enc_ec_k256_pkcs8_pem, EcK256, "ec-k256.pkcs8.encrypted.pem");
enc_test!(enc_ec_k256_pkcs8_der, EcK256, "ec-k256.pkcs8.encrypted.der");
