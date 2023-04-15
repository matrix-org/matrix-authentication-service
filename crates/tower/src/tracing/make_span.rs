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

use tracing::Span;

use super::enrich_span::EnrichSpan;
use crate::utils::FnWrapper;

/// A trait for creating a span for a request.
pub trait MakeSpan<R> {
    fn make_span(&self, request: &R) -> Span;
}

impl<R, F> MakeSpan<R> for FnWrapper<F>
where
    F: Fn(&R) -> Span,
{
    fn make_span(&self, request: &R) -> Span {
        (self.0)(request)
    }
}

/// Make span from a function.
pub fn make_span_fn<R, F>(f: F) -> FnWrapper<F>
where
    F: Fn(&R) -> Span,
{
    FnWrapper(f)
}

/// A macro to implement [`MakeSpan`] for a tuple of types, where the first type
/// implements [`MakeSpan`] and the rest implement [`EnrichSpan`].
macro_rules! impl_for_tuple {
    (M, $($T:ident),+) => {
        impl<R, M, $($T),+> MakeSpan<R> for (M, $($T),+)
        where
            M: MakeSpan<R>,
            $($T: EnrichSpan<R>),+
        {
            fn make_span(&self, request: &R) -> Span {
                #[allow(non_snake_case)]
                let (ref m, $(ref $T),+) = *self;

                let span = m.make_span(request);
                $(
                    $T.enrich_span(&span, request);
                )+
                span
            }
        }
    };
}

impl_for_tuple!(M, T1);
impl_for_tuple!(M, T1, T2);
impl_for_tuple!(M, T1, T2, T3);
impl_for_tuple!(M, T1, T2, T3, T4);
impl_for_tuple!(M, T1, T2, T3, T4, T5);
impl_for_tuple!(M, T1, T2, T3, T4, T5, T6);
impl_for_tuple!(M, T1, T2, T3, T4, T5, T6, T7);
impl_for_tuple!(M, T1, T2, T3, T4, T5, T6, T7, T8);
