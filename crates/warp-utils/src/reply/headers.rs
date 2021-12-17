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

//! Reply with a typed header from the [`headers`] crate.
//!
//! ```rust
//! extern crate headers;
//! extern crate warp;
//!
//! use warp::Reply;
//! use mas_warp_utils::reply::with_typed_header;
//!
//! let reply = r#"{"hello": "world"}"#;
//! let reply = with_typed_header(headers::ContentType::json(), reply);;
//! let response = reply.into_response();
//! assert_eq!(response.headers().get("Content-Type").unwrap().to_str().unwrap(), "application/json");
//! ```

use headers::{Header, HeaderMapExt};
use warp::Reply;

/// Add a typed header to a reply
pub fn with_typed_header<R, H>(header: H, reply: R) -> WithTypedHeader<R, H> {
    WithTypedHeader { reply, header }
}

/// A reply with a typed header set
pub struct WithTypedHeader<R, H> {
    reply: R,
    header: H,
}

impl<R, H> Reply for WithTypedHeader<R, H>
where
    R: Reply,
    H: Header + Send,
{
    fn into_response(self) -> warp::reply::Response {
        let mut res = self.reply.into_response();
        res.headers_mut().typed_insert(self.header);
        res
    }
}
