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

use std::sync::Arc;

use async_graphql::{
    extensions::{ApolloTracing, Tracing},
    http::{playground_source, GraphQLPlaygroundConfig, MultipartOptions},
};
use axum::{
    async_trait,
    extract::{BodyStream, RawQuery, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json, TypedHeader,
};
use axum_extra::extract::PrivateCookieJar;
use futures_util::TryStreamExt;
use headers::{authorization::Bearer, Authorization, ContentType, HeaderValue};
use hyper::header::CACHE_CONTROL;
use mas_axum_utils::{FancyError, SessionInfo, SessionInfoExt};
use mas_graphql::{Requester, Schema};
use mas_keystore::Encrypter;
use mas_matrix::HomeserverConnection;
use mas_storage::{
    BoxClock, BoxRepository, BoxRng, Clock, Repository, RepositoryError, SystemClock,
};
use mas_storage_pg::PgRepository;
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;
use sqlx::PgPool;
use tracing::{info_span, Instrument};

use crate::impl_from_error_for_route;

struct GraphQLState {
    pool: PgPool,
    homeserver_connection: Arc<dyn HomeserverConnection<Error = anyhow::Error>>,
}

#[async_trait]
impl mas_graphql::State for GraphQLState {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        let repo = PgRepository::from_pool(&self.pool)
            .await
            .map_err(RepositoryError::from_error)?;

        Ok(repo.map_err(RepositoryError::from_error).boxed())
    }

    fn homeserver_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error> {
        self.homeserver_connection.as_ref()
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
pub fn schema(
    pool: &PgPool,
    homeserver_connection: impl HomeserverConnection<Error = anyhow::Error> + 'static,
) -> Schema {
    let state = GraphQLState {
        pool: pool.clone(),
        homeserver_connection: Arc::new(homeserver_connection),
    };
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

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Loading of some database objects failed")]
    LoadFailed,

    #[error("Invalid access token")]
    InvalidToken,

    #[error("Missing scope")]
    MissingScope,

    #[error(transparent)]
    ParseRequest(#[from] async_graphql::ParseRequestError),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        sentry::capture_error(&self);

        match self {
            e @ (Self::Internal(_) | Self::LoadFailed) => {
                let error = async_graphql::Error::new_with_source(e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"errors": [error]})),
                )
                    .into_response()
            }

            Self::InvalidToken => {
                let error = async_graphql::Error::new("Invalid token");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"errors": [error]})),
                )
                    .into_response()
            }

            Self::MissingScope => {
                let error = async_graphql::Error::new("Missing urn:mas:graphql:* scope");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"errors": [error]})),
                )
                    .into_response()
            }

            Self::ParseRequest(e) => {
                let error = async_graphql::Error::new_with_source(e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"errors": [error]})),
                )
                    .into_response()
            }
        }
    }
}

async fn get_requester(
    clock: &impl Clock,
    mut repo: BoxRepository,
    session_info: SessionInfo,
    token: Option<&str>,
) -> Result<Requester, RouteError> {
    let requester = if let Some(token) = token {
        let token = repo
            .oauth2_access_token()
            .find_by_token(token)
            .await?
            .ok_or(RouteError::InvalidToken)?;

        let session = repo
            .oauth2_session()
            .lookup(token.session_id)
            .await?
            .ok_or(RouteError::LoadFailed)?;

        // XXX: The user_id should really be directly on the OAuth session
        let browser_session = repo
            .browser_session()
            .lookup(session.user_session_id)
            .await?
            .ok_or(RouteError::LoadFailed)?;

        let user = browser_session.user;

        if !token.is_valid(clock.now()) || !session.is_valid() || !user.is_valid() {
            return Err(RouteError::InvalidToken);
        }

        if !session.scope.contains("urn:mas:graphql:*") {
            return Err(RouteError::MissingScope);
        }

        Requester::OAuth2Session(session, user)
    } else {
        let maybe_session = session_info.load_session(&mut repo).await?;
        Requester::from(maybe_session)
    };
    repo.cancel().await?;
    Ok(requester)
}

pub async fn post(
    State(schema): State<Schema>,
    clock: BoxClock,
    repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    content_type: Option<TypedHeader<ContentType>>,
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
    body: BodyStream,
) -> Result<impl IntoResponse, RouteError> {
    let token = authorization
        .as_ref()
        .map(|TypedHeader(Authorization(bearer))| bearer.token());
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let requester = get_requester(&clock, repo, session_info, token).await?;

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
    clock: BoxClock,
    repo: BoxRepository,
    cookie_jar: PrivateCookieJar<Encrypter>,
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, FancyError> {
    let token = authorization
        .as_ref()
        .map(|TypedHeader(Authorization(bearer))| bearer.token());
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let requester = get_requester(&clock, repo, session_info, token).await?;

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
