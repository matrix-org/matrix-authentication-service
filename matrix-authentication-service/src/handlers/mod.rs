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

use std::{convert::Infallible, sync::Arc};

use sqlx::PgPool;
use tera::Tera;
use warp::{filters::BoxedFilter, wrap_fn, Filter, Rejection, Reply};

use crate::{config::RootConfig, filters::csrf::with_csrf};

mod health;
mod oauth2;
mod views;

async fn display_error(err: Rejection) -> Result<impl Reply, Infallible> {
    let ret = format!("{:?}", err);
    Ok(ret)
}

pub fn root(
    pool: PgPool,
    templates: Tera,
    config: &RootConfig,
) -> BoxedFilter<(impl warp::Reply,)> {
    let templates = Arc::new(templates);
    let with_csrf_token = config.csrf.clone().into_extract_filter();
    let with_pool = warp::any().map(move || pool.clone());
    let with_templates = warp::any().map(move || templates.clone());

    // TODO: this is ugly and leaks
    let csrf_cookie_name = Box::leak(Box::new(config.csrf.cookie_name.clone()));

    let cors = warp::cors().allow_any_origin();

    let health = warp::path("health")
        .and(warp::get())
        .and(with_pool.clone())
        .and_then(self::health::get)
        .boxed();

    let metadata = warp::path!(".well-known" / "openid-configuration")
        .and(warp::get())
        .and(self::oauth2::discovery::get(&config.oauth2))
        .with(cors);

    let index = warp::path::end()
        .and(warp::get())
        .and(with_templates.clone())
        .and(with_csrf_token.clone())
        .and(with_pool.clone())
        .and_then(self::views::index::get)
        .untuple_one()
        .with(wrap_fn(with_csrf(config.csrf.key, csrf_cookie_name)));

    let login = warp::path("login")
        .and(warp::get())
        .and(with_templates)
        .and(with_csrf_token)
        .and(with_pool)
        .and_then(self::views::login::get)
        .untuple_one()
        .with(wrap_fn(with_csrf(config.csrf.key, csrf_cookie_name)));

    health.or(index).or(login).or(metadata).boxed()

    // app.at("/").nest({
    //     let mut views = tide::with_state(state.clone());
    //     views.with(state.session_middleware());
    //     views.with(state.csrf_middleware());
    //     views.with(crate::middlewares::errors);

    //     views.at("/").get(self::views::index::get);

    //     views
    //         .at("/login")
    //         .get(self::views::login::get)
    //         .post(self::views::login::post);

    //     views
    //         .at("/reauth")
    //         .get(self::views::reauth::get)
    //         .post(self::views::reauth::post);

    //     views.at("/logout").post(self::views::logout::post);

    //     views
    //         .at("oauth2/authorize")
    //         .with(BrowserErrorHandler)
    //         .get(self::oauth2::authorization::get);

    //     views
    // });
}
