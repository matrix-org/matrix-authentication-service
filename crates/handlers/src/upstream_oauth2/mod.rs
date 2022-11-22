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

use axum::body::Full;
use mas_http::{BodyToBytesResponseLayer, ClientInitError, ClientLayer, HttpService};
use tower::{
    util::{MapErrLayer, MapRequestLayer},
    BoxError, Layer,
};

pub(crate) mod authorize;
pub(crate) mod callback;

async fn http_service(operation: &'static str) -> Result<HttpService, ClientInitError> {
    let client = (
        MapErrLayer::new(BoxError::from),
        MapRequestLayer::new(|req: hyper::Request<_>| req.map(Full::new)),
        BodyToBytesResponseLayer::default(),
        ClientLayer::new(operation),
    )
        .layer(mas_http::make_untraced_client().await?);

    Ok(HttpService::new(client))
}
