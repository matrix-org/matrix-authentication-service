// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use apalis_core::{job::Job, request::JobRequest};
use mas_storage::job::JobWithSpanContext;
use mas_tower::{
    make_span_fn, DurationRecorderLayer, FnWrapper, InFlightCounterLayer, TraceLayer, KV,
};
use opentelemetry::{Key, KeyValue};
use tracing::info_span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

const JOB_NAME: Key = Key::from_static_str("job.name");
const JOB_STATUS: Key = Key::from_static_str("job.status");

fn make_span_for_job_request<J>(req: &JobRequest<JobWithSpanContext<J>>) -> tracing::Span
where
    J: Job,
{
    let span = info_span!(
        "job.run",
        "otel.kind" = "consumer",
        "otel.status_code" = tracing::field::Empty,
        "job.id" = %req.id(),
        "job.attempts" = req.attempts(),
        "job.name" = J::NAME,
    );

    if let Some(context) = req.inner().span_context() {
        span.add_link(context);
    }

    span
}

type TraceLayerForJob<J> = TraceLayer<
    FnWrapper<fn(&JobRequest<JobWithSpanContext<J>>) -> tracing::Span>,
    KV<&'static str>,
    KV<&'static str>,
>;

pub(crate) fn trace_layer<J>() -> TraceLayerForJob<J>
where
    J: Job,
{
    TraceLayer::new(make_span_fn(
        make_span_for_job_request::<J> as fn(&JobRequest<JobWithSpanContext<J>>) -> tracing::Span,
    ))
    .on_response(KV("otel.status_code", "OK"))
    .on_error(KV("otel.status_code", "ERROR"))
}

pub(crate) fn metrics_layer<J>() -> (
    DurationRecorderLayer<KeyValue, KeyValue, KeyValue>,
    InFlightCounterLayer<KeyValue>,
)
where
    J: Job,
{
    let duration_recorder = DurationRecorderLayer::new("job.run.duration")
        .on_request(JOB_NAME.string(J::NAME))
        .on_response(JOB_STATUS.string("success"))
        .on_error(JOB_STATUS.string("error"));
    let in_flight_counter =
        InFlightCounterLayer::new("job.run.active").on_request(JOB_NAME.string(J::NAME));

    (duration_recorder, in_flight_counter)
}
