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

#[cfg(feature = "axum")]
use std::borrow::Cow;

use http::Request;
use opentelemetry::KeyValue;

use super::utils::http_method_str;

pub trait MakeMetricsLabels<R> {
    fn make_metrics_labels(&self, request: &R) -> Vec<KeyValue>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultMakeMetricsLabels;

impl<R> MakeMetricsLabels<R> for DefaultMakeMetricsLabels {
    fn make_metrics_labels(&self, _request: &R) -> Vec<KeyValue> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MetricsLabelsFromHttpRequest;

impl<B> MakeMetricsLabels<Request<B>> for MetricsLabelsFromHttpRequest {
    fn make_metrics_labels(&self, request: &Request<B>) -> Vec<KeyValue> {
        vec![KeyValue::new("method", http_method_str(request.method()))]
    }
}

#[cfg(feature = "axum")]
#[derive(Debug, Clone, Copy, Default)]
pub struct MetricsLabelsFromAxumRequest;

#[cfg(feature = "axum")]
impl<B> MakeMetricsLabels<Request<B>> for MetricsLabelsFromAxumRequest {
    fn make_metrics_labels(&self, request: &Request<B>) -> Vec<KeyValue> {
        let path: Cow<'static, str> = request
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map_or("FALLBACK".into(), |path| path.as_str().to_owned().into());

        vec![
            KeyValue::new("method", http_method_str(request.method())),
            KeyValue::new("route", path),
        ]
    }
}
