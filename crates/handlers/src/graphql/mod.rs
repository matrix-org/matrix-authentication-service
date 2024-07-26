// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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

#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use async_graphql::{
    extensions::Tracing,
    http::{playground_source, GraphQLPlaygroundConfig, MultipartOptions},
    EmptySubscription, InputObject,
};
use axum::{
    async_trait,
    body::Body,
    extract::{RawQuery, State as AxumState},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use axum_extra::typed_header::TypedHeader;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use headers::{authorization::Bearer, Authorization, ContentType, HeaderValue};
use hyper::header::CACHE_CONTROL;
use mas_axum_utils::{
    cookies::CookieJar, sentry::SentryEventID, FancyError, SessionInfo, SessionInfoExt,
};
use mas_data_model::{BrowserSession, Session, SiteConfig, User};
use mas_matrix::HomeserverConnection;
use mas_policy::{InstantiateError, Policy, PolicyFactory};
use mas_storage::{BoxClock, BoxRepository, BoxRng, Clock, RepositoryError, SystemClock};
use mas_storage_pg::PgRepository;
use opentelemetry_semantic_conventions::trace::{GRAPHQL_DOCUMENT, GRAPHQL_OPERATION_NAME};
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;
use sqlx::PgPool;
use tracing::{info_span, Instrument};
use ulid::Ulid;

mod model;
mod mutations;
mod query;
mod state;

pub use self::state::{BoxState, State};
use self::{
    model::{CreationEvent, Node},
    mutations::Mutation,
    query::Query,
};
use crate::{impl_from_error_for_route, passwords::PasswordManager, BoundActivityTracker};

#[cfg(test)]
mod tests;

struct GraphQLState {
    pool: PgPool,
    homeserver_connection: Arc<dyn HomeserverConnection<Error = anyhow::Error>>,
    policy_factory: Arc<PolicyFactory>,
    site_config: SiteConfig,
    password_manager: PasswordManager,
}

#[async_trait]
impl state::State for GraphQLState {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        let repo = PgRepository::from_pool(&self.pool)
            .await
            .map_err(RepositoryError::from_error)?;

        Ok(repo.boxed())
    }

    async fn policy(&self) -> Result<Policy, InstantiateError> {
        self.policy_factory.instantiate().await
    }

    fn password_manager(&self) -> PasswordManager {
        self.password_manager.clone()
    }

    fn site_config(&self) -> &SiteConfig {
        &self.site_config
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
    policy_factory: &Arc<PolicyFactory>,
    homeserver_connection: impl HomeserverConnection<Error = anyhow::Error> + 'static,
    site_config: SiteConfig,
    password_manager: PasswordManager,
) -> Schema {
    let state = GraphQLState {
        pool: pool.clone(),
        policy_factory: Arc::clone(policy_factory),
        homeserver_connection: Arc::new(homeserver_connection),
        site_config,
        password_manager,
    };
    let state: BoxState = Box::new(state);

    schema_builder().extension(Tracing).data(state).finish()
}

fn span_for_graphql_request(request: &async_graphql::Request) -> tracing::Span {
    let span = info_span!(
        "GraphQL operation",
        "otel.name" = tracing::field::Empty,
        "otel.kind" = "server",
        { GRAPHQL_DOCUMENT } = request.query,
        { GRAPHQL_OPERATION_NAME } = tracing::field::Empty,
    );

    if let Some(name) = &request.operation_name {
        span.record("otel.name", name);
        span.record(GRAPHQL_OPERATION_NAME, name);
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
        let event_id = sentry::capture_error(&self);

        let response = match self {
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
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

async fn get_requester(
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
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

        activity_tracker
            .record_oauth2_session(clock, &session)
            .await;

        // Load the user if there is one
        let user = if let Some(user_id) = session.user_id {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(RouteError::LoadFailed)?;
            Some(user)
        } else {
            None
        };

        // If there is a user for this session, check that it is not locked
        let user_valid = user.as_ref().map_or(true, User::is_valid);

        if !token.is_valid(clock.now()) || !session.is_valid() || !user_valid {
            return Err(RouteError::InvalidToken);
        }

        if !session.scope.contains("urn:mas:graphql:*") {
            return Err(RouteError::MissingScope);
        }

        Requester::OAuth2Session(Box::new((session, user)))
    } else {
        let maybe_session = session_info.load_session(&mut repo).await?;

        if let Some(session) = maybe_session.as_ref() {
            activity_tracker
                .record_browser_session(clock, session)
                .await;
        }

        Requester::from(maybe_session)
    };
    repo.cancel().await?;
    Ok(requester)
}

pub async fn post(
    AxumState(schema): AxumState<Schema>,
    clock: BoxClock,
    repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    cookie_jar: CookieJar,
    content_type: Option<TypedHeader<ContentType>>,
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
    body: Body,
) -> Result<impl IntoResponse, RouteError> {
    let body = body.into_data_stream();
    let token = authorization
        .as_ref()
        .map(|TypedHeader(Authorization(bearer))| bearer.token());
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let requester = get_requester(&clock, &activity_tracker, repo, session_info, token).await?;

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
    AxumState(schema): AxumState<Schema>,
    clock: BoxClock,
    repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    cookie_jar: CookieJar,
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, FancyError> {
    let token = authorization
        .as_ref()
        .map(|TypedHeader(Authorization(bearer))| bearer.token());
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let requester = get_requester(&clock, &activity_tracker, repo, session_info, token).await?;

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

pub type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;
pub type SchemaBuilder = async_graphql::SchemaBuilder<Query, Mutation, EmptySubscription>;

#[must_use]
pub fn schema_builder() -> SchemaBuilder {
    async_graphql::Schema::build(Query::new(), Mutation::new(), EmptySubscription)
        .register_output_type::<Node>()
        .register_output_type::<CreationEvent>()
}

/// The identity of the requester.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Requester {
    /// The requester presented no authentication information.
    #[default]
    Anonymous,

    /// The requester is a browser session, stored in a cookie.
    BrowserSession(Box<BrowserSession>),

    /// The requester is a `OAuth2` session, with an access token.
    OAuth2Session(Box<(Session, Option<User>)>),
}

trait OwnerId {
    fn owner_id(&self) -> Option<Ulid>;
}

impl OwnerId for User {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.id)
    }
}

impl OwnerId for BrowserSession {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.user.id)
    }
}

impl OwnerId for mas_data_model::UserEmail {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.user_id)
    }
}

impl OwnerId for Session {
    fn owner_id(&self) -> Option<Ulid> {
        self.user_id
    }
}

impl OwnerId for mas_data_model::CompatSession {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.user_id)
    }
}

impl OwnerId for mas_data_model::UpstreamOAuthLink {
    fn owner_id(&self) -> Option<Ulid> {
        self.user_id
    }
}

/// A dumb wrapper around a `Ulid` to implement `OwnerId` for it.
pub struct UserId(Ulid);

impl OwnerId for UserId {
    fn owner_id(&self) -> Option<Ulid> {
        Some(self.0)
    }
}

impl Requester {
    fn browser_session(&self) -> Option<&BrowserSession> {
        match self {
            Self::BrowserSession(session) => Some(session),
            Self::OAuth2Session(_) | Self::Anonymous => None,
        }
    }

    fn user(&self) -> Option<&User> {
        match self {
            Self::BrowserSession(session) => Some(&session.user),
            Self::OAuth2Session(tuple) => tuple.1.as_ref(),
            Self::Anonymous => None,
        }
    }

    fn oauth2_session(&self) -> Option<&Session> {
        match self {
            Self::OAuth2Session(tuple) => Some(&tuple.0),
            Self::BrowserSession(_) | Self::Anonymous => None,
        }
    }

    /// Returns true if the requester can access the resource.
    fn is_owner_or_admin(&self, resource: &impl OwnerId) -> bool {
        // If the requester is an admin, they can do anything.
        if self.is_admin() {
            return true;
        }

        // Otherwise, they must be the owner of the resource.
        let Some(owner_id) = resource.owner_id() else {
            return false;
        };

        let Some(user) = self.user() else {
            return false;
        };

        user.id == owner_id
    }

    fn is_admin(&self) -> bool {
        match self {
            Self::OAuth2Session(tuple) => {
                // TODO: is this the right scope?
                // This has to be in sync with the policy
                tuple.0.scope.contains("urn:mas:admin")
            }
            Self::BrowserSession(_) | Self::Anonymous => false,
        }
    }
}

impl From<BrowserSession> for Requester {
    fn from(session: BrowserSession) -> Self {
        Self::BrowserSession(Box::new(session))
    }
}

impl<T> From<Option<T>> for Requester
where
    T: Into<Requester>,
{
    fn from(session: Option<T>) -> Self {
        session.map(Into::into).unwrap_or_default()
    }
}

/// A filter for dates, with a lower bound and an upper bound
#[derive(InputObject, Default, Clone, Copy)]
pub struct DateFilter {
    /// The lower bound of the date range
    after: Option<DateTime<Utc>>,

    /// The upper bound of the date range
    before: Option<DateTime<Utc>>,
}
