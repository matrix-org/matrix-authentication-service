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

use std::string::FromUtf8Error;

use mas_data_model::UpstreamOAuthProvider;
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_keystore::{DecryptError, Encrypter, Keystore};
use mas_oidc_client::types::client_credentials::{ClientCredentials, JwtSigningMethod};
use thiserror::Error;
use url::Url;

pub(crate) mod authorize;
pub(crate) mod cache;
pub(crate) mod callback;
mod cookie;
pub(crate) mod link;

use self::cookie::UpstreamSessions as UpstreamSessionsCookie;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
enum ProviderCredentialsError {
    #[error("Provider doesn't have a client secret")]
    MissingClientSecret,

    #[error("Could not decrypt client secret")]
    DecryptClientSecret {
        #[from]
        inner: DecryptError,
    },

    #[error("Client secret is invalid")]
    InvalidClientSecret {
        #[from]
        inner: FromUtf8Error,
    },
}

fn client_credentials_for_provider(
    provider: &UpstreamOAuthProvider,
    token_endpoint: &Url,
    keystore: &Keystore,
    encrypter: &Encrypter,
) -> Result<ClientCredentials, ProviderCredentialsError> {
    let client_id = provider.client_id.clone();

    // Decrypt the client secret
    let client_secret = provider
        .encrypted_client_secret
        .as_deref()
        .map(|encrypted_client_secret| {
            let decrypted = encrypter.decrypt_string(encrypted_client_secret)?;
            let decrypted = String::from_utf8(decrypted)?;
            Ok::<_, ProviderCredentialsError>(decrypted)
        })
        .transpose()?;

    let client_credentials = match provider.token_endpoint_auth_method {
        OAuthClientAuthenticationMethod::None => ClientCredentials::None { client_id },
        OAuthClientAuthenticationMethod::ClientSecretPost => ClientCredentials::ClientSecretPost {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },
        OAuthClientAuthenticationMethod::ClientSecretBasic => {
            ClientCredentials::ClientSecretBasic {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
            }
        }
        OAuthClientAuthenticationMethod::ClientSecretJwt => ClientCredentials::ClientSecretJwt {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
            signing_algorithm: provider
                .token_endpoint_signing_alg
                .clone()
                .unwrap_or(JsonWebSignatureAlg::Rs256),
            token_endpoint: token_endpoint.clone(),
        },
        OAuthClientAuthenticationMethod::PrivateKeyJwt => ClientCredentials::PrivateKeyJwt {
            client_id,
            jwt_signing_method: JwtSigningMethod::Keystore(keystore.clone()),
            signing_algorithm: provider
                .token_endpoint_signing_alg
                .clone()
                .unwrap_or(JsonWebSignatureAlg::Rs256),
            token_endpoint: token_endpoint.clone(),
        },
        // XXX: The database should never have an unsupported method in it
        _ => unreachable!(),
    };

    Ok(client_credentials)
}
