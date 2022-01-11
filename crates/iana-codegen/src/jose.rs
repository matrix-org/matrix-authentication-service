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

use serde::Deserialize;

use crate::EnumEntry;

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum Usage {
    #[serde(rename = "alg")]
    Alg,
    #[serde(rename = "enc")]
    Enc,
    #[serde(rename = "JWK")]
    Jwk,
}

#[derive(Debug, Deserialize)]
enum Requirements {
    Required,
    #[serde(rename = "Recommended+")]
    RecommendedPlus,
    Recommended,
    #[serde(rename = "Recommended-")]
    RecommendedMinus,
    Optional,
    Prohibited,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebEncryptionSignatureAlgorithm {
    #[serde(rename = "Algorithm Name")]
    name: String,
    #[serde(rename = "Algorithm Description")]
    description: String,
    #[serde(rename = "Algorithm Usage Location(s)")]
    usage: Usage,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: Requirements,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "Algorithm Analysis Document(s)")]
    analysis: String,
}

impl EnumEntry for WebEncryptionSignatureAlgorithm {
    const URL: &'static str =
        "https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv";
    const SECTIONS: &'static [&'static str] =
        &["JsonWebSignatureAlgorithm", "JsonWebEncryptionAlgorithm"];

    fn key(&self) -> Option<&'static str> {
        match self.usage {
            Usage::Alg => Some("JsonWebSignatureAlgorithm"),
            Usage::Enc => Some("JsonWebEncryptionAlgorithm"),
            _ => None,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebEncryptionCompressionAlgorithm {
    #[serde(rename = "Compression Algorithm Value")]
    value: String,
    #[serde(rename = "Compression Algorithm Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebEncryptionCompressionAlgorithm {
    const URL: &'static str =
        "https://www.iana.org/assignments/jose/web-encryption-compression-algorithms.csv";
    const SECTIONS: &'static [&'static str] = &["JsonWebEncryptionCompressionAlgorithm"];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebEncryptionCompressionAlgorithm")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyType {
    #[serde(rename = "\"kty\" Parameter Value")]
    value: String,
    #[serde(rename = "Key Type Description")]
    description: String,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: Requirements,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyType {
    const URL: &'static str = "https://www.iana.org/assignments/jose/web-key-types.csv";
    const SECTIONS: &'static [&'static str] = &["JsonWebKeyType"];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyType")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyEllipticCurve {
    #[serde(rename = "Curve Name")]
    name: String,
    #[serde(rename = "Curve Description")]
    description: String,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: Requirements,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyEllipticCurve {
    const URL: &'static str = "https://www.iana.org/assignments/jose/web-key-elliptic-curve.csv";
    const SECTIONS: &'static [&'static str] =
        &["JsonWebKeyEcEllipticCurve", "JsonWebKeyOkpEllipticCurve"];

    fn key(&self) -> Option<&'static str> {
        if self.name.starts_with("P-") || self.name == "secp256k1" {
            Some("JsonWebKeyEcEllipticCurve")
        } else {
            Some("JsonWebKeyOkpEllipticCurve")
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyUse {
    #[serde(rename = "Use Member Value")]
    value: String,
    #[serde(rename = "Use Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyUse {
    const URL: &'static str = "https://www.iana.org/assignments/jose/web-key-use.csv";
    const SECTIONS: &'static [&'static str] = &["JsonWebKeyUse"];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyUse")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyOperation {
    #[serde(rename = "Key Operation Value")]
    name: String,
    #[serde(rename = "Key Operation Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyOperation {
    const URL: &'static str = "https://www.iana.org/assignments/jose/web-key-operations.csv";
    const SECTIONS: &'static [&'static str] = &["JsonWebKeyOperation"];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyOperation")
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}
