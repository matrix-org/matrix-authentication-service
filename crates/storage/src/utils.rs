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

//! Wrappers and useful type aliases

use rand_core::CryptoRngCore;

use crate::Clock;

/// A wrapper which is used to map the error type of a repository to another
pub struct MapErr<R, F> {
    pub(crate) inner: R,
    pub(crate) mapper: F,
    _private: (),
}

impl<R, F> MapErr<R, F> {
    /// Create a new [`MapErr`] wrapper from an inner repository and a mapper
    /// function
    #[must_use]
    pub fn new(inner: R, mapper: F) -> Self {
        Self {
            inner,
            mapper,
            _private: (),
        }
    }
}

/// A boxed [`Clock`]
pub type BoxClock = Box<dyn Clock + Send>;

/// A boxed random number generator
pub type BoxRng = Box<dyn CryptoRngCore + Send>;

/// A macro to implement a repository trait for the [`MapErr`] wrapper and for
/// [`Box<R>`]
#[macro_export]
macro_rules! repository_impl {
    ($repo_trait:ident:
        $(
            async fn $method:ident (
                &mut self
                $(, $arg:ident: $arg_ty:ty )*
                $(,)?
            ) -> Result<$ret_ty:ty, Self::Error>;
        )*
    ) => {
        #[::async_trait::async_trait]
        impl<R: ?Sized> $repo_trait for ::std::boxed::Box<R>
        where
            R: $repo_trait,
        {
            type Error = <R as $repo_trait>::Error;

            $(
                async fn $method (&mut self $(, $arg: $arg_ty)*) -> Result<$ret_ty, Self::Error> {
                    (**self).$method ( $($arg),* ).await
                }
            )*
        }

        #[::async_trait::async_trait]
        impl<R, F, E> $repo_trait for $crate::MapErr<R, F>
        where
            R: $repo_trait,
            F: FnMut(<R as $repo_trait>::Error) -> E + ::std::marker::Send + ::std::marker::Sync,
        {
            type Error = E;

            $(
                async fn $method (&mut self $(, $arg: $arg_ty)*) -> Result<$ret_ty, Self::Error> {
                    self.inner.$method ( $($arg),* ).await.map_err(&mut self.mapper)
                }
            )*
        }
    };
}
