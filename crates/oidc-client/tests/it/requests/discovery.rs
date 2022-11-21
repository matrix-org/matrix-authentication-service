// Copyright 2022 Kévin Commaille.
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

use assert_matches::assert_matches;
use mas_iana::oauth::{OAuthAuthorizationEndpointResponseType, PkceCodeChallengeMethod};
use mas_jose::jwa::SUPPORTED_SIGNING_ALGORITHMS;
use mas_oidc_client::{
    error::DiscoveryError,
    requests::discovery::{discover, insecure_discover},
};
use oauth2_types::oidc::{ProviderMetadata, SubjectType};
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, ResponseTemplate,
};

use crate::init_test;

fn provider_metadata(issuer: &Url) -> ProviderMetadata {
    ProviderMetadata {
        issuer: Some(issuer.clone()),
        authorization_endpoint: issuer.join("authorize").ok(),
        token_endpoint: issuer.join("token").ok(),
        jwks_uri: issuer.join("jwks").ok(),
        response_types_supported: Some(vec![OAuthAuthorizationEndpointResponseType::Code.into()]),
        subject_types_supported: Some(vec![SubjectType::Pairwise, SubjectType::Public]),
        id_token_signing_alg_values_supported: Some(SUPPORTED_SIGNING_ALGORITHMS.into()),
        code_challenge_methods_supported: Some(vec![PkceCodeChallengeMethod::S256]),
        ..Default::default()
    }
}

#[tokio::test]
async fn pass_discover() {
    let (http_service, mock_server, issuer) = init_test().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(provider_metadata(&issuer)))
        .mount(&mock_server)
        .await;

    let provider_metadata = insecure_discover(&http_service, &issuer).await.unwrap();

    assert_eq!(*provider_metadata.issuer(), issuer);
}

#[tokio::test]
async fn fail_discover_404() {
    let (http_service, _mock_server, issuer) = init_test().await;

    let error = discover(&http_service, &issuer).await.unwrap_err();

    assert_matches!(error, DiscoveryError::Http(_));
}

#[tokio::test]
async fn fail_discover_not_json() {
    let (http_service, mock_server, issuer) = init_test().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let error = discover(&http_service, &issuer).await.unwrap_err();

    assert_matches!(error, DiscoveryError::FromJson(_));
}

#[tokio::test]
async fn fail_discover_invalid_metadata() {
    let (http_service, mock_server, issuer) = init_test().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ProviderMetadata::default()))
        .mount(&mock_server)
        .await;

    let error = discover(&http_service, &issuer).await.unwrap_err();

    assert_matches!(error, DiscoveryError::Validation(_));
}
