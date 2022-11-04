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

use std::{borrow::Cow, str::FromStr, time::Duration};

use async_graphql::{
    extensions::{ApolloTracing, Tracing},
    futures_util::TryStreamExt,
    http::{
        playground_source, GraphQLPlaygroundConfig, MultipartOptions, WebSocketProtocols,
        WsMessage, ALL_WEBSOCKET_PROTOCOLS,
    },
    Context, Data, EmptyMutation,
};
use axum::{
    extract::{
        ws::{CloseFrame, Message},
        BodyStream, RawQuery, State, WebSocketUpgrade,
    },
    response::{Html, IntoResponse, Response},
    Json, TypedHeader,
};
use axum_extra::extract::PrivateCookieJar;
use futures_util::{SinkExt, Stream, StreamExt};
use headers::{ContentType, Header, HeaderValue};
use hyper::header::{CACHE_CONTROL, SEC_WEBSOCKET_PROTOCOL};
use mas_axum_utils::{FancyError, SessionInfo, SessionInfoExt};
use mas_keystore::Encrypter;
use sqlx::PgPool;
use tracing::{info_span, Instrument};

pub type Schema = async_graphql::Schema<Query, EmptyMutation, Subscription>;

#[must_use]
pub fn schema(pool: &PgPool) -> Schema {
    async_graphql::Schema::build(Query::new(pool), EmptyMutation, Subscription)
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
    cookie_jar: PrivateCookieJar<Encrypter>,
    content_type: Option<TypedHeader<ContentType>>,
    body: BodyStream,
) -> Result<impl IntoResponse, FancyError> {
    let content_type = content_type.map(|TypedHeader(h)| h.to_string());

    let (session_info, _cookie_jar) = cookie_jar.session_info();

    let request = async_graphql::http::receive_batch_body(
        content_type,
        body.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .into_async_read(),
        MultipartOptions::default(),
    )
    .await? // XXX: this should probably return another error response?
    .data(session_info);

    let response = match request {
        async_graphql::BatchRequest::Single(request) => {
            let span = span_for_graphql_request(&request);
            let response = schema.execute(request).instrument(span).await;
            async_graphql::BatchResponse::Single(response)
        }
        async_graphql::BatchRequest::Batch(requests) => async_graphql::BatchResponse::Batch(
            futures_util::stream::iter(requests.into_iter())
                .then(|request| {
                    let span = span_for_graphql_request(&request);
                    schema.execute(request).instrument(span)
                })
                .collect()
                .await,
        ),
    };

    let cache_control = response
        .cache_control()
        .value()
        .and_then(|v| HeaderValue::from_str(&v).ok())
        .map(|h| [(CACHE_CONTROL, h)]);

    let headers = response.http_headers();

    Ok((headers, cache_control, Json(response)))
}

pub async fn get(
    State(schema): State<Schema>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, FancyError> {
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    let request =
        async_graphql::http::parse_query_string(&query.unwrap_or_default())?.data(session_info);

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

pub struct SecWebsocketProtocol(WebSocketProtocols);

impl Header for SecWebsocketProtocol {
    fn name() -> &'static headers::HeaderName {
        &SEC_WEBSOCKET_PROTOCOL
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .find_map(|p| WebSocketProtocols::from_str(p.trim()).ok())
            .map(Self)
            .ok_or_else(headers::Error::invalid)
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if let Ok(v) = HeaderValue::from_str(self.0.sec_websocket_protocol()) {
            values.extend(std::iter::once(v));
        }
    }
}

pub async fn ws(
    State(schema): State<Schema>,
    cookie_jar: PrivateCookieJar<Encrypter>,
    TypedHeader(SecWebsocketProtocol(protocol)): TypedHeader<SecWebsocketProtocol>,
    websocket: WebSocketUpgrade,
) -> Response {
    let (session_info, _cookie_jar) = cookie_jar.session_info();
    websocket
        .protocols(ALL_WEBSOCKET_PROTOCOLS)
        .on_upgrade(move |ws| async move {
            let (mut sink, stream) = ws.split();
            let stream = stream
                .take_while(|res| std::future::ready(res.is_ok()))
                .map(Result::unwrap)
                .filter_map(|msg| {
                    if let Message::Text(_) | Message::Binary(_) = msg {
                        std::future::ready(Some(msg.into_data()))
                    } else {
                        std::future::ready(None)
                    }
                });

            let mut data = Data::default();
            data.insert(session_info);

            let mut stream = async_graphql::http::WebSocket::new(schema.clone(), stream, protocol)
                .connection_data(data)
                .map(|msg| match msg {
                    WsMessage::Text(text) => Message::Text(text),
                    WsMessage::Close(code, status) => Message::Close(Some(CloseFrame {
                        code,
                        reason: Cow::from(status),
                    })),
                });

            while let Some(item) = stream.next().await {
                let _res = sink.send(item).await;
            }
        })
}

pub async fn playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql")
            .subscription_endpoint("/graphql/ws")
            .with_setting("request.credentials", "include"),
    ))
}

pub struct Query {
    database: PgPool,
}

impl Query {
    fn new(pool: &PgPool) -> Self {
        Self {
            database: pool.clone(),
        }
    }
}

#[async_graphql::Object]
impl Query {
    async fn username(&self, ctx: &Context<'_>) -> Result<Option<String>, async_graphql::Error> {
        let mut conn = self.database.acquire().await?;
        let session_info = ctx.data::<SessionInfo>()?;
        let session = session_info.load_session(&mut conn).await?;

        Ok(session.map(|s| s.user.username))
    }
}

pub struct Subscription;

#[async_graphql::Subscription]
impl Subscription {
    async fn integers(&self, #[graphql(default = 1)] step: i32) -> impl Stream<Item = i32> {
        let mut value = 0;
        tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(1)))
            .map(move |_| {
                value += step;
                value
            })
    }
}
