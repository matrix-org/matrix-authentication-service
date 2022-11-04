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

use headers::{ContentLength, HeaderMapExt};
use http::Response;
#[cfg(feature = "client")]
use hyper::client::connect::HttpInfo;
use opentelemetry::{trace::SpanRef, KeyValue};
use opentelemetry_semantic_conventions::trace as SC;

pub trait OnResponse<R> {
    fn on_response(&self, span: &SpanRef<'_>, metrics_labels: &mut Vec<KeyValue>, response: &R);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultOnResponse;

impl<R> OnResponse<R> for DefaultOnResponse {
    fn on_response(&self, _span: &SpanRef<'_>, _metrics_labels: &mut Vec<KeyValue>, _response: &R) {
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OnHttpResponse;

impl<B> OnResponse<Response<B>> for OnHttpResponse {
    fn on_response(
        &self,
        span: &SpanRef<'_>,
        metrics_labels: &mut Vec<KeyValue>,
        response: &Response<B>,
    ) {
        let status_code = i64::from(response.status().as_u16());
        span.set_attribute(SC::HTTP_STATUS_CODE.i64(status_code));
        metrics_labels.push(KeyValue::new("status_code", status_code));

        if let Some(ContentLength(content_length)) = response.headers().typed_get() {
            if let Ok(content_length) = content_length.try_into() {
                span.set_attribute(SC::HTTP_RESPONSE_CONTENT_LENGTH.i64(content_length));
            }
        }

        #[cfg(feature = "client")]
        // Get local and remote address from hyper's HttpInfo injected by the
        // HttpConnector
        if let Some(info) = response.extensions().get::<HttpInfo>() {
            span.set_attribute(SC::NET_PEER_IP.string(info.remote_addr().ip().to_string()));
            span.set_attribute(SC::NET_PEER_PORT.i64(info.remote_addr().port().into()));
            span.set_attribute(SC::NET_HOST_IP.string(info.local_addr().ip().to_string()));
            span.set_attribute(SC::NET_HOST_PORT.i64(info.local_addr().port().into()));
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OnAwsResponse;

impl OnResponse<aws_smithy_http::operation::Response> for OnAwsResponse {
    fn on_response(
        &self,
        span: &SpanRef<'_>,
        metrics_labels: &mut Vec<KeyValue>,
        response: &aws_smithy_http::operation::Response,
    ) {
        let response = response.http();
        let status_code = i64::from(response.status().as_u16());
        span.set_attribute(SC::HTTP_STATUS_CODE.i64(status_code));
        metrics_labels.push(KeyValue::new("status_code", status_code));

        if let Some(ContentLength(content_length)) = response.headers().typed_get() {
            if let Ok(content_length) = content_length.try_into() {
                span.set_attribute(SC::HTTP_RESPONSE_CONTENT_LENGTH.i64(content_length));
            }
        }

        #[cfg(feature = "client")]
        // Get local and remote address from hyper's HttpInfo injected by the
        // HttpConnector
        if let Some(info) = response.extensions().get::<HttpInfo>() {
            span.set_attribute(SC::NET_PEER_IP.string(info.remote_addr().ip().to_string()));
            span.set_attribute(SC::NET_PEER_PORT.i64(info.remote_addr().port().into()));
            span.set_attribute(SC::NET_HOST_IP.string(info.local_addr().ip().to_string()));
            span.set_attribute(SC::NET_HOST_PORT.i64(info.local_addr().port().into()));
        }
    }
}
