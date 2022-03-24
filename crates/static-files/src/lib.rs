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

//! Serve static files used by the web frontend

#![forbid(unsafe_code)]
#![deny(clippy::all, missing_docs, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]

use std::{
    convert::Infallible,
    future::{ready, Ready},
};

use axum::{
    body::{boxed, Full},
    response::{IntoResponse, Response},
};
use headers::{ContentLength, ContentType, HeaderMapExt};
use http::{Request, StatusCode};
use rust_embed::RustEmbed;
use tower::Service;

// TODO: read the assets live from the filesystem

/// Embedded public assets
#[derive(RustEmbed, Clone)]
#[folder = "public/"]
pub struct Assets;

impl Assets {
    fn get_response(path: &str) -> Option<Response> {
        let asset = Self::get(path)?;

        let len = asset.data.len().try_into().unwrap();
        let mime = mime_guess::from_path(path).first_or_octet_stream();

        let mut res = Response::new(boxed(Full::from(asset.data)));
        res.headers_mut().typed_insert(ContentType::from(mime));
        res.headers_mut().typed_insert(ContentLength(len));
        Some(res)
    }
}

impl<B> Service<Request<B>> for Assets {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let path = req.uri().path().trim_start_matches('/');
        // TODO: support HEAD requests
        // TODO: support ETag
        // TODO: support range requests
        let response =
            Self::get_response(path).unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
        ready(Ok(response))
    }
}
