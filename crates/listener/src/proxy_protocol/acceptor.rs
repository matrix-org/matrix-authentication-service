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

use futures_util::ready;
use hyper::server::accept::Accept;

use super::ProxyStream;

pin_project_lite::pin_project! {
    pub struct ProxyAcceptor<A> {
        #[pin]
        inner: A,
    }
}

impl<A> ProxyAcceptor<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

impl<A> Accept for ProxyAcceptor<A>
where
    A: Accept,
{
    type Conn = ProxyStream<A::Conn>;
    type Error = A::Error;

    fn poll_accept(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Conn, Self::Error>>> {
        let res = match ready!(self.project().inner.poll_accept(cx)) {
            Some(Ok(stream)) => Some(Ok(ProxyStream::new(stream))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        };

        std::task::Poll::Ready(res)
    }
}
