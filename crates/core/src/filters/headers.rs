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
//
use headers::{Header, HeaderMapExt, HeaderValue};
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection, Reply};

/// Add a typed header to a reply
pub fn typed_header<R, H>(header: H, reply: R) -> WithTypedHeader<R, H> {
    WithTypedHeader { reply, header }
}

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

#[derive(Debug, Error)]
#[error("could not decode header {1}")]
pub struct InvalidTypedHeader(#[source] headers::Error, &'static str);

impl Reject for InvalidTypedHeader {}

/// Extract a typed header from the request
///
/// # Rejections
///
/// This can reject with either a [`warp::reject::MissingHeader`] or a
/// [`InvalidTypedHeader`].
pub fn with_typed_header<T: Header + Send + 'static>(
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static {
    warp::header::value(T::name().as_str()).and_then(decode_typed_header)
}

async fn decode_typed_header<T: Header>(header: HeaderValue) -> Result<T, Rejection> {
    let mut it = std::iter::once(&header);
    let decoded = T::decode(&mut it).map_err(|e| InvalidTypedHeader(e, T::name().as_str()))?;
    Ok(decoded)
}
