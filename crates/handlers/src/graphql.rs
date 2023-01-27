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

use async_graphql::{
    extensions::{ApolloTracing, Tracing},
    http::{playground_source, GraphQLPlaygroundConfig, MultipartOptions},
};
use axum::{
    extract::{BodyStream, RawQuery, State},
    response::{Html, IntoResponse},
    Json, TypedHeader,
};
use axum_extra::extract::PrivateCookieJar;
use futures_util::TryStreamExt;
use headers::{ContentType, HeaderValue};
use hyper::header::CACHE_CONTROL;
use mas_axum_utils::{FancyError, SessionInfoExt};
use mas_graphql::Schema;
use mas_keystore::Encrypter;
use mas_storage::BoxRepository;
use tokio::sync::Mutex;
use tracing::{info_span, Instrument};

#[must_use]
pub fn schema() -> Schema {
    mas_graphql::schema_builder()
        .extension(Tracing)
        .extension(ApolloTracing)
        .finish()
}

fn span_for_graphql_request(request: &async_graphql::Request) -> tracing::Span {
    let span = info_span!(
        "GraphQL operation",
        "otel.name" = tracing::field::Empty,
        "otel.kind" = "server",
        "graphql.document" = request.query,
        "graphql.operation.name" = tracing::field::Empty,
    );

    if let Some(name) = &request.operation_name {
        span.record("otel.name", name);
        span.record("graphql.operation.name", name);
    }

    span
}

pub async fn post(
    State(schema): State<Schema>,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    content_type: Option<TypedHeader<ContentType>>,
    body: BodyStream,
) -> Result<impl IntoResponse, FancyError> {
    let content_type = content_type.map(|TypedHeader(h)| h.to_string());

    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let maybe_session = session_info.load_session(&mut repo).await?;

    let mut request = async_graphql::http::receive_body(
        content_type,
        body.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .into_async_read(),
        MultipartOptions::default(),
    )
    .await? // XXX: this should probably return another error response?
    .data(Mutex::new(repo));

    if let Some(session) = maybe_session {
        request = request.data(session);
    }

    let span = span_for_graphql_request(&request);
    let response = schema.execute(request).instrument(span).await;

    let cache_control = response
        .cache_control
        .value()
        .and_then(|v| HeaderValue::from_str(&v).ok())
        .map(|h| [(CACHE_CONTROL, h)]);

    let headers = response.http_headers.clone();

    Ok((headers, cache_control, Json(response)))
}

pub async fn get(
    State(schema): State<Schema>,
    mut repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, FancyError> {
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let maybe_session = session_info.load_session(&mut repo).await?;

    let mut request =
        async_graphql::http::parse_query_string(&query.unwrap_or_default())?.data(Mutex::new(repo));

    if let Some(session) = maybe_session {
        request = request.data(session);
    }

    let span = span_for_graphql_request(&request);
    let response = schema.execute(request).instrument(span).await;

    let cache_control = response
        .cache_control
        .value()
        .and_then(|v| HeaderValue::from_str(&v).ok())
        .map(|h| [(CACHE_CONTROL, h)]);

    let headers = response.http_headers.clone();

    Ok((headers, cache_control, Json(response)))
}

pub async fn playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql").with_setting("request.credentials", "include"),
    ))
}
