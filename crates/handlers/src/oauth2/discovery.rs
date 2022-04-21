// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use std::sync::Arc;

use axum::{extract::Extension, response::IntoResponse, Json};
use mas_axum_utils::UrlBuilder;
use mas_iana::{
    jose::JsonWebSignatureAlg,
    oauth::{
        OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod,
        PkceCodeChallengeMethod,
    },
};
use mas_jose::{SigningKeystore, StaticKeystore};
use oauth2_types::{
    oidc::{ClaimType, Metadata, SubjectType},
    requests::{Display, GrantType, Prompt, ResponseMode},
    scope,
};

#[allow(clippy::too_many_lines)]
pub(crate) async fn get(
    Extension(key_store): Extension<Arc<StaticKeystore>>,
    Extension(url_builder): Extension<UrlBuilder>,
) -> impl IntoResponse {
    // This is how clients can authenticate
    let client_auth_methods_supported = Some(vec![
        OAuthClientAuthenticationMethod::ClientSecretBasic,
        OAuthClientAuthenticationMethod::ClientSecretPost,
        OAuthClientAuthenticationMethod::ClientSecretJwt,
        OAuthClientAuthenticationMethod::PrivateKeyJwt,
        OAuthClientAuthenticationMethod::None,
    ]);

    let client_auth_signing_alg_values_supported = Some(vec![
        JsonWebSignatureAlg::Hs256,
        JsonWebSignatureAlg::Hs384,
        JsonWebSignatureAlg::Hs512,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs512,
    ]);

    // This is how we can sign stuff
    let jwt_signing_alg_values_supported = Some({
        let algs = key_store.supported_algorithms();
        let mut algs = Vec::from_iter(algs);
        algs.sort();
        algs
    });

    // Prepare all the endpoints
    let issuer = Some(url_builder.oidc_issuer());
    let authorization_endpoint = Some(url_builder.oauth_authorization_endpoint());
    let token_endpoint = Some(url_builder.oauth_token_endpoint());
    let jwks_uri = Some(url_builder.jwks_uri());
    let introspection_endpoint = Some(url_builder.oauth_introspection_endpoint());
    let userinfo_endpoint = Some(url_builder.oidc_userinfo_endpoint());
    let registration_endpoint = Some(url_builder.oauth_registration_endpoint());

    let scopes_supported = Some(vec![scope::OPENID.to_string(), scope::EMAIL.to_string()]);

    let response_types_supported = Some(vec![
        OAuthAuthorizationEndpointResponseType::Code,
        OAuthAuthorizationEndpointResponseType::Token,
        OAuthAuthorizationEndpointResponseType::IdToken,
        OAuthAuthorizationEndpointResponseType::CodeToken,
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
        OAuthAuthorizationEndpointResponseType::IdTokenToken,
        OAuthAuthorizationEndpointResponseType::CodeIdToken,
    ]);

    let response_modes_supported = Some(vec![
        ResponseMode::FormPost,
        ResponseMode::Query,
        ResponseMode::Fragment,
    ]);

    let grant_types_supported = Some(vec![
        GrantType::AuthorizationCode,
        GrantType::Implicit,
        GrantType::RefreshToken,
    ]);

    let token_endpoint_auth_methods_supported = client_auth_methods_supported.clone();
    let token_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported.clone();

    let introspection_endpoint_auth_methods_supported = client_auth_methods_supported;
    let introspection_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported;

    let code_challenge_methods_supported = Some(vec![
        PkceCodeChallengeMethod::Plain,
        PkceCodeChallengeMethod::S256,
    ]);

    let subject_types_supported = Some(vec![SubjectType::Public]);

    let id_token_signing_alg_values_supported = jwt_signing_alg_values_supported.clone();
    let userinfo_signing_alg_values_supported = jwt_signing_alg_values_supported;

    let display_values_supported = Some(vec![Display::Page]);

    let claim_types_supported = Some(vec![ClaimType::Normal]);

    let claims_supported = Some(vec![
        "iss".to_string(),
        "sub".to_string(),
        "aud".to_string(),
        "iat".to_string(),
        "exp".to_string(),
        "nonce".to_string(),
        "auth_time".to_string(),
        "at_hash".to_string(),
        "c_hash".to_string(),
    ]);

    let claims_parameter_supported = Some(false);
    let request_parameter_supported = Some(false);
    let request_uri_parameter_supported = Some(false);

    let prompt_values_supported = Some(vec![Prompt::None, Prompt::Login, Prompt::Create]);

    let metadata = Metadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        registration_endpoint,
        scopes_supported,
        response_types_supported,
        response_modes_supported,
        grant_types_supported,
        token_endpoint_auth_methods_supported,
        token_endpoint_auth_signing_alg_values_supported,
        introspection_endpoint,
        introspection_endpoint_auth_methods_supported,
        introspection_endpoint_auth_signing_alg_values_supported,
        code_challenge_methods_supported,
        userinfo_endpoint,
        subject_types_supported,
        id_token_signing_alg_values_supported,
        userinfo_signing_alg_values_supported,
        display_values_supported,
        claim_types_supported,
        claims_supported,
        claims_parameter_supported,
        request_parameter_supported,
        request_uri_parameter_supported,
        prompt_values_supported,
        ..Metadata::default()
    };

    Json(metadata)
}
