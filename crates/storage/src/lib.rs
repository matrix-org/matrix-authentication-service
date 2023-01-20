// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

//! Interactions with the database

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    clippy::future_not_send,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

use rand_core::CryptoRngCore;

pub mod clock;
pub mod pagination;
pub(crate) mod repository;

pub mod compat;
pub mod oauth2;
pub mod upstream_oauth2;
pub mod user;

pub use self::{
    clock::{Clock, SystemClock},
    pagination::{Page, Pagination},
    repository::{BoxRepository, Repository, RepositoryError},
};

pub struct MapErr<Repository, Mapper> {
    inner: Repository,
    mapper: Mapper,
}

impl<Repository, Mapper> MapErr<Repository, Mapper> {
    fn new(inner: Repository, mapper: Mapper) -> Self {
        Self { inner, mapper }
    }
}

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

pub type BoxClock = Box<dyn Clock + Send>;
pub type BoxRng = Box<dyn CryptoRngCore + Send>;
