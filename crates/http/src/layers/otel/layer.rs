use std::sync::Arc;

use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
use tower::Layer;

use super::{
    extract_context::DefaultExtractContext, inject_context::DefaultInjectContext,
    make_span_builder::DefaultMakeSpanBuilder, on_error::DefaultOnError,
    on_response::DefaultOnResponse, service::Trace,
};

#[derive(Debug, Clone)]
pub struct TraceLayer<
    ExtractContext = DefaultExtractContext,
    InjectContext = DefaultInjectContext,
    MakeSpanBuilder = DefaultMakeSpanBuilder,
    OnResponse = DefaultOnResponse,
    OnError = DefaultOnError,
> {
    tracer: Arc<opentelemetry::global::BoxedTracer>,
    extract_context: ExtractContext,
    inject_context: InjectContext,
    make_span_builder: MakeSpanBuilder,
    on_response: OnResponse,
    on_error: OnError,

    inflight_requests: UpDownCounter<i64>,
    request_counter: Counter<u64>,
    request_histogram: Histogram<f64>,
}

impl Default for TraceLayer {
    fn default() -> Self {
        Self::with_namespace("http")
    }
}

impl TraceLayer {
    #[must_use]
    pub fn with_namespace(namespace: &'static str) -> Self {
        let tracer = Arc::new(opentelemetry::global::tracer("mas-http"));
        let meter = opentelemetry::global::meter("mas-http");

        let inflight_requests = meter
            .i64_up_down_counter(format!("{namespace}.inflight_requests"))
            .with_description("Number of in-flight requests")
            .init();
        let request_counter = meter
            .u64_counter(format!("{namespace}.requests_total"))
            .with_description("Total number of requests made.")
            .init();
        let request_histogram = meter
            .f64_histogram(format!("{namespace}.request_duration_seconds"))
            .with_description("The request latencies in seconds.")
            .init();

        Self::new(
            tracer,
            inflight_requests,
            request_counter,
            request_histogram,
        )
    }
}

impl<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError>
    TraceLayer<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError>
{
    #[must_use]
    pub fn new(
        tracer: Arc<opentelemetry::global::BoxedTracer>,
        inflight_requests: UpDownCounter<i64>,
        request_counter: Counter<u64>,
        request_histogram: Histogram<f64>,
    ) -> Self
    where
        ExtractContext: Default,
        InjectContext: Default,
        MakeSpanBuilder: Default,
        OnResponse: Default,
        OnError: Default,
    {
        Self {
            tracer,
            extract_context: ExtractContext::default(),
            inject_context: InjectContext::default(),
            make_span_builder: MakeSpanBuilder::default(),
            on_response: OnResponse::default(),
            on_error: OnError::default(),
            inflight_requests,
            request_counter,
            request_histogram,
        }
    }

    #[must_use]
    pub fn extract_context<NewExtractContext>(
        self,
        extract_context: NewExtractContext,
    ) -> TraceLayer<NewExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError> {
        TraceLayer {
            tracer: self.tracer,
            extract_context,
            inject_context: self.inject_context,
            make_span_builder: self.make_span_builder,
            on_response: self.on_response,
            on_error: self.on_error,
            inflight_requests: self.inflight_requests,
            request_counter: self.request_counter,
            request_histogram: self.request_histogram,
        }
    }

    #[must_use]
    pub fn inject_context<NewInjectContext>(
        self,
        inject_context: NewInjectContext,
    ) -> TraceLayer<ExtractContext, NewInjectContext, MakeSpanBuilder, OnResponse, OnError> {
        TraceLayer {
            tracer: self.tracer,
            extract_context: self.extract_context,
            inject_context,
            make_span_builder: self.make_span_builder,
            on_response: self.on_response,
            on_error: self.on_error,
            inflight_requests: self.inflight_requests,
            request_counter: self.request_counter,
            request_histogram: self.request_histogram,
        }
    }

    #[must_use]
    pub fn make_span_builder<NewMakeSpanBuilder>(
        self,
        make_span_builder: NewMakeSpanBuilder,
    ) -> TraceLayer<ExtractContext, InjectContext, NewMakeSpanBuilder, OnResponse, OnError> {
        TraceLayer {
            tracer: self.tracer,
            extract_context: self.extract_context,
            inject_context: self.inject_context,
            make_span_builder,
            on_response: self.on_response,
            on_error: self.on_error,
            inflight_requests: self.inflight_requests,
            request_counter: self.request_counter,
            request_histogram: self.request_histogram,
        }
    }

    #[must_use]
    pub fn on_response<NewOnResponse>(
        self,
        on_response: NewOnResponse,
    ) -> TraceLayer<ExtractContext, InjectContext, MakeSpanBuilder, NewOnResponse, OnError> {
        TraceLayer {
            tracer: self.tracer,
            extract_context: self.extract_context,
            inject_context: self.inject_context,
            make_span_builder: self.make_span_builder,
            on_response,
            on_error: self.on_error,
            inflight_requests: self.inflight_requests,
            request_counter: self.request_counter,
            request_histogram: self.request_histogram,
        }
    }

    #[must_use]
    pub fn on_error<NewOnError>(
        self,
        on_error: NewOnError,
    ) -> TraceLayer<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, NewOnError> {
        TraceLayer {
            tracer: self.tracer,
            extract_context: self.extract_context,
            inject_context: self.inject_context,
            make_span_builder: self.make_span_builder,
            on_response: self.on_response,
            on_error,
            inflight_requests: self.inflight_requests,
            request_counter: self.request_counter,
            request_histogram: self.request_histogram,
        }
    }
}

impl<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError, S> Layer<S>
    for TraceLayer<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError>
where
    ExtractContext: Clone,
    InjectContext: Clone,
    MakeSpanBuilder: Clone,
    OnResponse: Clone,
    OnError: Clone,
{
    type Service = Trace<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError, S>;

    fn layer(&self, inner: S) -> Self::Service {
        Trace::new(
            inner,
            self.tracer.clone(),
            self.extract_context.clone(),
            self.inject_context.clone(),
            self.make_span_builder.clone(),
            self.on_response.clone(),
            self.on_error.clone(),
            self.inflight_requests.clone(),
            self.request_counter.clone(),
            self.request_histogram.clone(),
        )
    }
}
