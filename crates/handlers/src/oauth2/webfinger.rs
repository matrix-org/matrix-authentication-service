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

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use axum_extra::typed_header::TypedHeader;
use headers::ContentType;
use mas_router::UrlBuilder;
use oauth2_types::webfinger::WebFingerResponse;
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Params {
    resource: String,

    // TODO: handle multiple rel=
    #[serde(default)]
    rel: Option<String>,
}

fn jrd() -> mime::Mime {
    "application/jrd+json".parse().unwrap()
}

#[tracing::instrument(name = "handlers.oauth2.webfinger.get", skip_all)]
pub(crate) async fn get(
    Query(params): Query<Params>,
    State(url_builder): State<UrlBuilder>,
) -> impl IntoResponse {
    // TODO: should we validate the subject?
    let subject = params.resource;

    let wants_issuer = params
        .rel
        .iter()
        .any(|i| i == "http://openid.net/specs/connect/1.0/issuer");

    let res = if wants_issuer {
        WebFingerResponse::new(subject).with_issuer(url_builder.oidc_issuer())
    } else {
        WebFingerResponse::new(subject)
    };

    (TypedHeader(ContentType::from(jrd())), Json(res))
}
