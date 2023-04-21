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
    async_trait,
    extract::{BodyStream, RawQuery, State},
    response::{Html, IntoResponse},
    Json, TypedHeader,
};
use axum_extra::extract::PrivateCookieJar;
use futures_util::TryStreamExt;
use headers::{ContentType, HeaderValue};
use hyper::header::CACHE_CONTROL;
use mas_axum_utils::{FancyError, SessionInfoExt};
use mas_graphql::{Requester, Schema};
use mas_keystore::Encrypter;
use mas_storage::{BoxClock, BoxRepository, BoxRng, Repository, RepositoryError, SystemClock};
use mas_storage_pg::PgRepository;
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;
use sqlx::PgPool;
use tracing::{info_span, Instrument};

struct GraphQLState {
    pool: PgPool,
}

#[async_trait]
impl mas_graphql::State for GraphQLState {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        let repo = PgRepository::from_pool(&self.pool)
            .await
            .map_err(RepositoryError::from_error)?;

        Ok(repo.map_err(RepositoryError::from_error).boxed())
    }

    fn clock(&self) -> BoxClock {
        let clock = SystemClock::default();
        Box::new(clock)
    }

    fn rng(&self) -> BoxRng {
        #[allow(clippy::disallowed_methods)]
        let rng = thread_rng();

        let rng = ChaChaRng::from_rng(rng).expect("Failed to seed rng");
        Box::new(rng)
    }
}

#[must_use]
pub fn schema(pool: &PgPool) -> Schema {
    let state = GraphQLState { pool: pool.clone() };
    let state: mas_graphql::BoxState = Box::new(state);

    mas_graphql::schema_builder()
        .extension(Tracing)
        .extension(ApolloTracing)
        .data(state)
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
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let maybe_session = session_info.load_session(&mut repo).await?;
    let requester = Requester::from(maybe_session);
    repo.cancel().await?;

    let content_type = content_type.map(|TypedHeader(h)| h.to_string());

    let request = async_graphql::http::receive_body(
        content_type,
        body.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .into_async_read(),
        MultipartOptions::default(),
    )
    .await?
    .data(requester); // XXX: this should probably return another error response?

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
    let requester = Requester::from(maybe_session);
    repo.cancel().await?;

    let request =
        async_graphql::http::parse_query_string(&query.unwrap_or_default())?.data(requester);

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
