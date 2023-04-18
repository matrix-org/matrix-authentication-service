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

use async_trait::async_trait;
use aws_config::provider_config::ProviderConfig;
use aws_sdk_sesv2::{
    middleware::DefaultMiddleware,
    operation::send_email::{SendEmailError, SendEmailOutput},
    primitives::Blob,
    types::{EmailContent, RawMessage},
    Client,
};
use aws_smithy_async::rt::sleep::TokioSleep;
use aws_smithy_client::erase::{DynConnector, DynMiddleware};
use headers::{ContentLength, HeaderMapExt, Host, UserAgent};
use lettre::{address::Envelope, AsyncTransport};
use mas_http::ClientInitError;
use mas_tower::{enrich_span_fn, make_span_fn, TraceContextLayer, TraceLayer};
use tracing::{info_span, Span};

pub type Error = aws_smithy_client::SdkError<SendEmailError>;

/// An asynchronous email transport that sends email via the AWS Simple Email
/// Service v2 API
pub struct Transport {
    client: Client,
}

impl Transport {
    /// Construct a [`Transport`] from the environment
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client failed to initialize
    pub async fn from_env() -> Result<Self, ClientInitError> {
        let sleep = Arc::new(TokioSleep::new());

        // Create the TCP connector from mas-http. This way we share the root
        // certificate loader with it
        let http_connector = mas_http::make_traced_connector()
            .await
            .expect("failed to create HTTPS connector");

        let http_connector = aws_smithy_client::hyper_ext::Adapter::builder()
            .sleep_impl(sleep.clone())
            .build(http_connector);

        let http_connector = DynConnector::new(http_connector);

        // Middleware to add tracing to AWS SDK operations
        let middleware = DynMiddleware::new((
            DefaultMiddleware::default(),
            // TODO: factor this out somewhere else
            TraceLayer::new(make_span_fn(|op: &aws_smithy_http::operation::Request| {
                let properties = op.properties();
                let request = op.http();
                let span = info_span!(
                    "aws.sdk.operation",
                    "otel.kind" = "client",
                    "otel.name" = tracing::field::Empty,
                    "otel.status_code" = tracing::field::Empty,
                    "rpc.system" = "aws-api",
                    "rpc.service" = tracing::field::Empty,
                    "rpc.method" = tracing::field::Empty,
                    "http.method" = %request.method(),
                    "http.url" = %request.uri(),
                    "http.host" = tracing::field::Empty,
                    "http.request_content_length" = tracing::field::Empty,
                    "http.response_content_length" = tracing::field::Empty,
                    "http.status_code" = tracing::field::Empty,
                    "user_agent.original" = tracing::field::Empty,
                );

                if let Some(metadata) = properties.get::<aws_smithy_http::operation::Metadata>() {
                    span.record("rpc.service", metadata.service());
                    span.record("rpc.method", metadata.name());
                    let name = format!("{}::{}", metadata.service(), metadata.name());
                    span.record("otel.name", name);
                } else if let Some(service) = properties.get::<aws_types::SigningService>() {
                    span.record("rpc.service", tracing::field::debug(service));
                    span.record("otel.name", tracing::field::debug(service));
                }

                let headers = request.headers();

                if let Some(host) = headers.typed_get::<Host>() {
                    span.record("http.host", tracing::field::display(host));
                }

                if let Some(user_agent) = headers.typed_get::<UserAgent>() {
                    span.record("user_agent.original", tracing::field::display(user_agent));
                }

                if let Some(ContentLength(content_length)) = headers.typed_get() {
                    span.record("http.request_content_length", content_length);
                }

                span
            }))
            .on_response(enrich_span_fn(
                |span: &Span, res: &aws_smithy_http::operation::Response| {
                    span.record("otel.status_code", "OK");
                    let response = res.http();

                    let status = response.status();
                    span.record("http.status_code", status.as_u16());

                    let headers = response.headers();
                    if let Some(ContentLength(content_length)) = headers.typed_get() {
                        span.record("http.response_content_length", content_length);
                    }
                },
            ))
            .on_error(enrich_span_fn(
                |span: &Span, err: &aws_smithy_http_tower::SendOperationError| {
                    span.record("otel.status_code", "ERROR");
                    span.record("exception.message", tracing::field::debug(err));
                },
            )),
            TraceContextLayer::new(),
        ));

        // Use that connector for discovering the config
        let config = ProviderConfig::default().with_http_connector(http_connector.clone());
        let config = aws_config::from_env().configure(config).load().await;
        let config = aws_sdk_sesv2::Config::from(&config);

        // As well as for the client itself
        let client = aws_smithy_client::Client::builder()
            .sleep_impl(sleep)
            .connector(http_connector)
            .middleware(middleware)
            .build_dyn();

        let client = Client::with_config(client, config);
        Ok(Self { client })
    }
}

#[async_trait]
impl AsyncTransport for Transport {
    type Ok = SendEmailOutput;
    type Error = Error;

    async fn send_raw(&self, _envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        let email = Blob::new(email);
        let email = RawMessage::builder().data(email).build();
        let email = EmailContent::builder().raw(email).build();

        let request = self.client.send_email().content(email);
        let response = request.send().await?;

        Ok(response)
    }
}
