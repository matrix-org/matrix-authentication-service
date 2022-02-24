use std::sync::Arc;

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
}

impl Default for TraceLayer {
    fn default() -> Self {
        let tracer = Arc::new(opentelemetry::global::tracer("mas-http"));
        Self::new(tracer)
    }
}

impl<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError>
    TraceLayer<ExtractContext, InjectContext, MakeSpanBuilder, OnResponse, OnError>
{
    #[must_use]
    pub fn new(tracer: Arc<opentelemetry::global::BoxedTracer>) -> Self
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
        Trace {
            inner,
            tracer: self.tracer.clone(),
            extract_context: self.extract_context.clone(),
            inject_context: self.inject_context.clone(),
            make_span_builder: self.make_span_builder.clone(),
            on_response: self.on_response.clone(),
            on_error: self.on_error.clone(),
        }
    }
}
