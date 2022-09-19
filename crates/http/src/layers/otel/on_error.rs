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

use opentelemetry::{trace::SpanRef, KeyValue};
use opentelemetry_semantic_conventions::trace::EXCEPTION_MESSAGE;

pub trait OnError<E> {
    fn on_error(&self, span: &SpanRef<'_>, err: &E) -> Vec<KeyValue>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultOnError;

impl<E> OnError<E> for DefaultOnError
where
    E: std::fmt::Display,
{
    fn on_error(&self, span: &SpanRef<'_>, err: &E) -> Vec<KeyValue> {
        let attributes = vec![EXCEPTION_MESSAGE.string(err.to_string())];
        span.add_event("exception".to_owned(), attributes);

        Vec::new()
    }
}
