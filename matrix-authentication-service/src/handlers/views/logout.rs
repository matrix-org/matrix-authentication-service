// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use warp::{filters::BoxedFilter, hyper::Uri, wrap_fn, Filter, Rejection, Reply};

use crate::{
    config::CsrfConfig,
    csrf::CsrfForm,
    errors::WrapError,
    filters::{csrf::with_csrf, CsrfToken},
};

pub(super) fn filter(csrf_config: &CsrfConfig) -> BoxedFilter<(impl Reply,)> {
    // TODO: this is ugly and leaks
    let csrf_cookie_name = Box::leak(Box::new(csrf_config.cookie_name.clone()));

    warp::post()
        .and(warp::path("logout"))
        .and(csrf_config.to_extract_filter())
        .and(warp::body::form())
        .and_then(|token: CsrfToken, form: CsrfForm<()>| async {
            form.verify_csrf(&token).wrap_error()?;
            Ok::<_, Rejection>((token, warp::redirect(Uri::from_static("/login"))))
        })
        .untuple_one()
        .with(wrap_fn(with_csrf(csrf_config.key, csrf_cookie_name)))
        .boxed()
}
