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

use std::sync::Arc;

use mas_jose::StaticKeystore;
use mas_warp_utils::filters;
use tower::{Service, ServiceExt};
use warp::{filters::BoxedFilter, Filter, Rejection, Reply};

pub(super) fn filter(key_store: &Arc<StaticKeystore>) -> BoxedFilter<(Box<dyn Reply>,)> {
    let key_store = key_store.clone();
    warp::path!("oauth2" / "keys.json")
        .and(filters::trace::name("GET /oauth2/keys.json"))
        .and(warp::get().map(move || key_store.clone()).and_then(get))
        .boxed()
}

async fn get(key_store: Arc<StaticKeystore>) -> Result<Box<dyn Reply>, Rejection> {
    let mut key_store: &StaticKeystore = key_store.as_ref();
    let jwks = key_store.ready().await?.call(()).await?;
    Ok(Box::new(warp::reply::json(&jwks)))
}
