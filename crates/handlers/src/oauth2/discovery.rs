// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::collections::HashSet;

use mas_config::OAuth2Config;
use oauth2_types::{
    oidc::{ClaimType, Metadata, SigningAlgorithm, SubjectType},
    pkce::CodeChallengeMethod,
    requests::{ClientAuthenticationMethod, Display, GrantType, ResponseMode},
};
use warp::{filters::BoxedFilter, Filter, Reply};

#[allow(clippy::too_many_lines)]
pub(super) fn filter(config: &OAuth2Config) -> BoxedFilter<(Box<dyn Reply>,)> {
    let base = config.issuer.clone();

    // This is how clients can authenticate
    let client_auth_methods_supported = Some({
        let mut s = HashSet::new();
        s.insert(ClientAuthenticationMethod::ClientSecretBasic);
        s.insert(ClientAuthenticationMethod::ClientSecretPost);
        s.insert(ClientAuthenticationMethod::ClientSecretJwt);
        s.insert(ClientAuthenticationMethod::PrivateKeyJwt);
        s.insert(ClientAuthenticationMethod::None);
        s
    });

    let client_auth_signing_alg_values_supported = Some({
        let mut s = HashSet::new();
        s.insert(SigningAlgorithm::Hs256);
        s.insert(SigningAlgorithm::Hs384);
        s.insert(SigningAlgorithm::Hs512);
        s.insert(SigningAlgorithm::Rs256);
        s.insert(SigningAlgorithm::Rs384);
        s.insert(SigningAlgorithm::Rs512);
        s
    });

    // This is how we can sign stuff
    // TODO: query the signing store
    let jwt_signing_alg_values_supported = Some({
        let mut s = HashSet::new();
        s.insert(SigningAlgorithm::Rs256);
        s.insert(SigningAlgorithm::Rs384);
        s.insert(SigningAlgorithm::Rs512);
        s.insert(SigningAlgorithm::Es256);
        s
    });

    // Prepare all the endpoints
    let issuer = Some(base.clone());
    let authorization_endpoint = base.join("oauth2/authorize").ok();
    let token_endpoint = base.join("oauth2/token").ok();
    let jwks_uri = base.join("oauth2/keys.json").ok();
    let introspection_endpoint = base.join("oauth2/introspect").ok();
    let userinfo_endpoint = base.join("oauth2/userinfo").ok();

    let scopes_supported = Some({
        let mut s = HashSet::new();
        s.insert("openid".to_string());
        s
    });

    let response_types_supported = Some({
        let mut s = HashSet::new();
        s.insert("code".to_string());
        s.insert("token".to_string());
        s.insert("id_token".to_string());
        s.insert("code token".to_string());
        s.insert("code id_token".to_string());
        s.insert("token id_token".to_string());
        s.insert("code token id_token".to_string());
        s
    });

    let response_modes_supported = Some({
        let mut s = HashSet::new();
        s.insert(ResponseMode::FormPost);
        s.insert(ResponseMode::Query);
        s.insert(ResponseMode::Fragment);
        s
    });

    let grant_types_supported = Some({
        let mut s = HashSet::new();
        s.insert(GrantType::AuthorizationCode);
        s.insert(GrantType::RefreshToken);
        s
    });

    let token_endpoint_auth_methods_supported = client_auth_methods_supported.clone();
    let token_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported.clone();

    let introspection_endpoint_auth_methods_supported = client_auth_methods_supported;
    let introspection_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported;

    let code_challenge_methods_supported = Some({
        let mut s = HashSet::new();
        s.insert(CodeChallengeMethod::Plain);
        s.insert(CodeChallengeMethod::S256);
        s
    });

    let subject_types_supported = Some({
        let mut s = HashSet::new();
        s.insert(SubjectType::Public);
        s
    });

    let id_token_signing_alg_values_supported = jwt_signing_alg_values_supported;

    let display_values_supported = Some({
        let mut s = HashSet::new();
        s.insert(Display::Page);
        s
    });

    let claim_types_supported = Some({
        let mut s = HashSet::new();
        s.insert(ClaimType::Normal);
        s
    });

    let claims_supported = Some({
        let mut s = HashSet::new();
        s.insert("iss".to_string());
        s.insert("sub".to_string());
        s.insert("aud".to_string());
        s.insert("iat".to_string());
        s.insert("exp".to_string());
        s.insert("nonce".to_string());
        s.insert("auth_time".to_string());
        s.insert("at_hash".to_string());
        s.insert("c_hash".to_string());
        s
    });

    let claims_parameter_supported = Some(false);
    let request_parameter_supported = Some(false);
    let request_uri_parameter_supported = Some(false);

    let metadata = Metadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
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
        display_values_supported,
        claim_types_supported,
        claims_supported,
        claims_parameter_supported,
        request_parameter_supported,
        request_uri_parameter_supported,
        ..Metadata::default()
    };

    warp::path!(".well-known" / "openid-configuration")
        .and(warp::get())
        .map(move || {
            let ret: Box<dyn Reply> = Box::new(warp::reply::json(&metadata));
            ret
        })
        .boxed()
}
