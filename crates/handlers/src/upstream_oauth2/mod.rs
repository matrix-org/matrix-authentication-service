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

use anyhow::Context;
use axum::body::Full;
use mas_data_model::UpstreamOAuthProvider;
use mas_http::{BodyToBytesResponseLayer, ClientInitError, ClientLayer, HttpService};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_keystore::{Encrypter, Keystore};
use mas_oidc_client::types::client_credentials::{ClientCredentials, JwtSigningMethod};
use thiserror::Error;
use tower::{
    util::{MapErrLayer, MapRequestLayer},
    BoxError, Layer,
};
use url::Url;

pub(crate) mod authorize;
pub(crate) mod callback;

#[derive(Debug, Error)]
enum ProviderCredentialsError {
    #[error("Provider doesn't have a client secret")]
    MissingClientSecret,

    #[error("Could not decrypt client secret")]
    InvalidClientSecret {
        #[source]
        inner: anyhow::Error,
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
            encrypter
                .decrypt_string(encrypted_client_secret)
                .and_then(|client_secret| {
                    String::from_utf8(client_secret)
                        .context("Client secret contains non-UTF8 bytes")
                })
                .map_err(|inner| ProviderCredentialsError::InvalidClientSecret { inner })
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

async fn http_service(operation: &'static str) -> Result<HttpService, ClientInitError> {
    let client = (
        MapErrLayer::new(BoxError::from),
        MapRequestLayer::new(|req: hyper::Request<_>| req.map(Full::new)),
        BodyToBytesResponseLayer::default(),
        ClientLayer::new(operation),
    )
        .layer(mas_http::make_untraced_client().await?);

    Ok(HttpService::new(client))
}
