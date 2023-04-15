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

use opentelemetry::{KeyValue, Value};

use crate::{utils::KV, FnWrapper};

/// Make metrics attributes from a type.
pub trait MetricsAttributes<T> {
    type Iter<'a>: Iterator<Item = KeyValue>
    where
        Self: 'a,
        T: 'a;

    fn attributes<'a>(&'a self, t: &'a T) -> Self::Iter<'a>;
}

pub fn metrics_attributes_fn<T, F>(f: F) -> FnWrapper<F>
where
    F: Fn(&T) -> Vec<KeyValue> + 'static,
    T: 'static,
{
    FnWrapper(f)
}

impl<T, F> MetricsAttributes<T> for FnWrapper<F>
where
    F: Fn(&T) -> Vec<KeyValue> + 'static,
    T: 'static,
{
    type Iter<'a> = std::vec::IntoIter<KeyValue>;

    fn attributes<'a>(&'a self, t: &'a T) -> Self::Iter<'a> {
        let values: Vec<KeyValue> = self.0(t);
        values.into_iter()
    }
}

impl<T> MetricsAttributes<T> for ()
where
    T: 'static,
{
    type Iter<'a> = std::iter::Empty<KeyValue>;

    fn attributes(&self, _t: &T) -> Self::Iter<'_> {
        std::iter::empty()
    }
}

impl<V, T> MetricsAttributes<T> for Vec<V>
where
    V: MetricsAttributes<T> + 'static,
    T: 'static,
{
    type Iter<'a> = Box<dyn Iterator<Item = KeyValue> + 'a>;
    fn attributes<'a>(&'a self, t: &'a T) -> Self::Iter<'_> {
        Box::new(self.iter().flat_map(|v| v.attributes(t)))
    }
}

impl<V, T> MetricsAttributes<T> for KV<V>
where
    V: Into<Value> + Clone + 'static,
    T: 'static,
{
    type Iter<'a> = std::iter::Once<KeyValue>;
    fn attributes(&self, _t: &T) -> Self::Iter<'_> {
        std::iter::once(KeyValue::new(self.0, self.1.clone().into()))
    }
}

impl<T> MetricsAttributes<T> for KeyValue
where
    T: 'static,
{
    type Iter<'a> = std::iter::Once<KeyValue>;
    fn attributes(&self, _t: &T) -> Self::Iter<'_> {
        std::iter::once(self.clone())
    }
}

impl<V, T> MetricsAttributes<T> for Option<V>
where
    V: MetricsAttributes<T> + 'static,
    T: 'static,
{
    type Iter<'a> = std::iter::Flatten<std::option::IntoIter<V::Iter<'a>>>;

    fn attributes<'a>(&'a self, t: &'a T) -> Self::Iter<'_> {
        self.as_ref().map(|v| v.attributes(t)).into_iter().flatten()
    }
}

macro_rules! chain_for {
    // Sub-macro for reversing the list of types.
    (@reverse ($( $reversed:ident ,)*)) => {
        chain_for!(@build_chain $($reversed),*)
    };
    (@reverse ($($reversed:ident,)*) $head:ident $(, $tail:ident)*) => {
        chain_for!(@reverse ($head, $($reversed,)*) $($tail),*)
    };

    // Sub-macro for building the chain of iterators.
    (@build_chain $last:ident) => {
        $last::Iter<'a>
    };
    (@build_chain $head:ident, $($tail:ident),*) => {
        std::iter::Chain<chain_for!(@build_chain $($tail),*), $head::Iter<'a>>
    };

    ($($idents:ident),+) => {
        chain_for!(@reverse () $($idents),+)
    };
}

macro_rules! impl_for_tuple {
    ($first:ident $(,$rest:ident)*) => {
        impl<T, $first, $($rest,)*> MetricsAttributes<T> for ($first, $($rest,)*)
        where
            T: 'static,
            $first: MetricsAttributes<T> + 'static,
            $($rest: MetricsAttributes<T> + 'static,)*
        {
            type Iter<'a> = chain_for!($first $(, $rest)*);
            fn attributes<'a>(&'a self, t: &'a T) -> Self::Iter<'a> {
                #[allow(non_snake_case)]
                let (head, $($rest,)*) = self;
                head.attributes(t)
                    $(.chain($rest.attributes(t)))*
            }
        }
    };
}

impl_for_tuple!(V1);
impl_for_tuple!(V1, V2);
impl_for_tuple!(V1, V2, V3);
impl_for_tuple!(V1, V2, V3, V4);
impl_for_tuple!(V1, V2, V3, V4, V5);
impl_for_tuple!(V1, V2, V3, V4, V5, V6);
impl_for_tuple!(V1, V2, V3, V4, V5, V6, V7);
impl_for_tuple!(V1, V2, V3, V4, V5, V6, V7, V8);
impl_for_tuple!(V1, V2, V3, V4, V5, V6, V7, V8, V9);
