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

use std::path::PathBuf;

use warp::{filters::BoxedFilter, Filter, Reply};

#[cfg(not(feature = "dev"))]
mod builtin {
    use std::{fmt::Write, str::FromStr};

    use headers::{ContentLength, ContentType, ETag, HeaderMapExt};
    use rust_embed::RustEmbed;
    use warp::{
        filters::BoxedFilter, hyper::StatusCode, path::Tail, reply::Response, Filter, Rejection,
        Reply,
    };

    #[derive(RustEmbed)]
    #[folder = "public/"]
    struct Asset;

    #[allow(clippy::unused_async)]
    async fn serve_embed(
        path: Tail,
        if_none_match: Option<String>,
    ) -> Result<Box<dyn Reply>, Rejection> {
        let path = path.as_str();
        let asset = Asset::get(path).ok_or_else(warp::reject::not_found)?;

        // TODO: this etag calculation is ugly
        let etag = {
            let mut s = String::with_capacity(32 * 2 + 2);
            write!(s, "\"").unwrap();
            for b in asset.metadata.sha256_hash() {
                write!(s, "{:02x}", b).unwrap();
            }
            write!(s, "\"").unwrap();
            s
        };

        if Some(&etag) == if_none_match.as_ref() {
            return Ok(Box::new(StatusCode::NOT_MODIFIED));
        };

        let len = asset.data.len().try_into().unwrap();
        let mime = mime_guess::from_path(path).first_or_octet_stream();

        let mut res = Response::new(asset.data.into());
        res.headers_mut().typed_insert(ContentType::from(mime));
        res.headers_mut().typed_insert(ContentLength(len));
        res.headers_mut()
            .typed_insert(ETag::from_str(&etag).unwrap());
        Ok(Box::new(res))
    }

    pub(crate) fn filter() -> BoxedFilter<(impl Reply,)> {
        warp::path::tail()
            .and(warp::filters::header::optional("If-None-Match"))
            .and_then(serve_embed)
            .boxed()
    }
}

#[cfg(feature = "dev")]
mod builtin {
    use std::path::PathBuf;

    use warp::{filters::BoxedFilter, Reply};

    pub(crate) fn filter() -> BoxedFilter<(impl Reply,)> {
        let path = PathBuf::from(format!("{}/public", env!("CARGO_MANIFEST_DIR")));
        super::filter_for_path(path)
    }
}

fn box_reply(reply: impl Reply + 'static) -> Box<dyn Reply> {
    Box::new(reply)
}

fn filter_for_path(path: PathBuf) -> BoxedFilter<(impl Reply,)> {
    warp::fs::dir(path).boxed()
}

/// [`warp`] filter that serves static files
#[must_use]
pub fn filter(path: Option<PathBuf>) -> BoxedFilter<(Box<dyn Reply>,)> {
    let f = self::builtin::filter();

    if let Some(path) = path {
        f.or(filter_for_path(path)).map(box_reply).boxed()
    } else {
        f.map(box_reply).boxed()
    }
}
