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

//! Serve static files used by the web frontend

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]

#[cfg(not(feature = "dev"))]
mod builtin {
    use std::{
        fmt::Write,
        future::{ready, Ready},
    };

    use axum::{
        response::{IntoResponse, Response},
        TypedHeader,
    };
    use headers::{ContentLength, ContentType, ETag, HeaderMapExt, IfNoneMatch};
    use http::{Method, Request, StatusCode};
    use rust_embed::RustEmbed;
    use tower::Service;

    /// Embedded public assets
    #[derive(RustEmbed, Clone, Debug)]
    #[folder = "public/"]
    pub struct Assets;

    impl Assets {
        fn get_response(
            is_head: bool,
            path: &str,
            if_none_match: Option<IfNoneMatch>,
        ) -> Option<Response> {
            let asset = Self::get(path)?;

            let etag = {
                let hash = asset.metadata.sha256_hash();
                let mut buf = String::with_capacity(2 + hash.len() * 2);
                write!(buf, "\"").unwrap();
                for byte in hash {
                    write!(buf, "{:02x}", byte).unwrap();
                }
                write!(buf, "\"").unwrap();
                buf
            };
            let etag: ETag = etag.parse().unwrap();

            if let Some(if_none_match) = if_none_match {
                if if_none_match.precondition_passes(&etag) {
                    return Some(StatusCode::NOT_MODIFIED.into_response());
                }
            }

            let len = asset.data.len().try_into().unwrap();
            let mime = mime_guess::from_path(path).first_or_octet_stream();

            let headers = (
                TypedHeader(ContentType::from(mime)),
                TypedHeader(ContentLength(len)),
                TypedHeader(etag),
            );

            let res = if is_head {
                headers.into_response()
            } else {
                (headers, asset.data).into_response()
            };

            Some(res)
        }
    }

    impl<B> Service<Request<B>> for Assets {
        type Response = Response;
        type Error = std::io::Error;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<B>) -> Self::Future {
            let (parts, _body) = req.into_parts();
            let path = parts.uri.path().trim_start_matches('/');
            let if_none_match = parts.headers.typed_get();
            let is_head = match parts.method {
                Method::GET => false,
                Method::HEAD => true,
                _ => return ready(Ok(StatusCode::METHOD_NOT_ALLOWED.into_response())),
            };

            // TODO: support range requests
            let response = Self::get_response(is_head, path, if_none_match)
                .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
            ready(Ok(response))
        }
    }

    /// Serve static files
    #[must_use]
    pub fn service() -> Assets {
        Assets
    }
}

#[cfg(feature = "dev")]
mod builtin {
    use std::path::PathBuf;

    use tower_http::services::ServeDir;

    /// Serve static files in dev mode
    #[must_use]
    pub fn service() -> ServeDir {
        let path = PathBuf::from(format!("{}/public", env!("CARGO_MANIFEST_DIR")));
        ServeDir::new(path).append_index_html_on_directories(false)
    }
}

use std::{convert::Infallible, future::ready, path::PathBuf};

use axum::{
    body::HttpBody,
    response::Response,
    routing::{on_service, MethodFilter},
};
use http::{Request, StatusCode};
use tower::{util::BoxCloneService, ServiceExt};
use tower_http::services::ServeDir;

/// Serve static files
#[must_use]
pub fn service<B: HttpBody + Send + 'static>(
    path: &Option<PathBuf>,
) -> BoxCloneService<Request<B>, Response, Infallible> {
    let svc = if let Some(path) = path {
        let handler = ServeDir::new(path).append_index_html_on_directories(false);
        on_service(MethodFilter::HEAD | MethodFilter::GET, handler)
    } else {
        let builtin = self::builtin::service();
        on_service(MethodFilter::HEAD | MethodFilter::GET, builtin)
    };

    svc.handle_error(|_| ready(StatusCode::INTERNAL_SERVER_ERROR))
        .boxed_clone()
}
