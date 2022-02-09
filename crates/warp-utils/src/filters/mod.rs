// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

//! Set of [`warp`] filters

#![allow(clippy::unused_async)] // Some warp filters need that
#![deny(missing_docs)]

pub mod authenticate;
pub mod client;
pub mod cookies;
pub mod cors;
pub mod csrf;
pub mod database;
pub mod headers;
pub mod session;
pub mod trace;
pub mod url_builder;

use std::convert::Infallible;

use mas_templates::Templates;
use warp::{Filter, Rejection};

pub use self::csrf::CsrfToken;

/// Get the [`Templates`]
#[must_use]
pub fn with_templates(
    templates: &Templates,
) -> impl Filter<Extract = (Templates,), Error = Infallible> + Clone + Send + Sync + 'static {
    let templates = templates.clone();
    warp::any().map(move || templates.clone())
}

/// Recover a particular rejection type with a `None` option variant
///
/// # Example
///
/// ```rust
/// extern crate warp;
///
/// use warp::{filters::header::header, reject::MissingHeader, Filter};
///
/// use mas_warp_utils::filters::none_on_error;
///
/// header("Content-Length")
///     .map(Some)
///     .recover(none_on_error::<_, MissingHeader>)
///     .unify()
///     .map(|length: Option<u64>| {
///       format!("header: {:?}", length)
///     });
/// ```
pub async fn none_on_error<T, E: 'static>(rejection: Rejection) -> Result<Option<T>, Rejection> {
    if rejection.find::<E>().is_some() {
        Ok(None)
    } else {
        Err(rejection)
    }
}
