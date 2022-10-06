// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except proxied: streamliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::ready;
use hyper::server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{stream::HandshakeNotDone, ProxyProtocolV1Info, ProxyStream};

pin_project_lite::pin_project! {
    pub struct MaybeProxyAcceptor<A> {
        proxied: bool,

        #[pin]
        inner: A,
    }
}

impl<A> MaybeProxyAcceptor<A> {
    #[must_use]
    pub const fn new(inner: A, proxied: bool) -> Self {
        Self { proxied, inner }
    }

    pub const fn is_proxied(&self) -> bool {
        self.proxied
    }
}

impl<A> Deref for MaybeProxyAcceptor<A> {
    type Target = A;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<A> Accept for MaybeProxyAcceptor<A>
where
    A: Accept,
{
    type Conn = MaybeProxyStream<A::Conn>;
    type Error = A::Error;

    fn poll_accept(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Conn, Self::Error>>> {
        let proj = self.project();
        let res = match ready!(proj.inner.poll_accept(cx)) {
            Some(Ok(stream)) => Some(Ok(MaybeProxyStream::new(stream, *proj.proxied))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        };

        std::task::Poll::Ready(res)
    }
}

pin_project_lite::pin_project! {
    #[project = MaybeProxyStreamProj]
    pub enum MaybeProxyStream<S> {
        Proxied { #[pin] stream: ProxyStream<S> },
        NotProxied { #[pin] stream: S },
    }
}

impl<S> MaybeProxyStream<S> {
    pub const fn new(stream: S, proxied: bool) -> Self {
        if proxied {
            Self::Proxied {
                stream: ProxyStream::new(stream),
            }
        } else {
            Self::NotProxied { stream }
        }
    }

    /// Get informations from the proxied connection, if it was procied
    ///
    /// # Errors
    ///
    /// Returns an error if the stream did not complete the handshake yet
    pub fn proxy_info(&self) -> Result<Option<&ProxyProtocolV1Info>, HandshakeNotDone> {
        match self {
            Self::Proxied { stream } => Ok(Some(stream.proxy_info()?)),
            Self::NotProxied { .. } => Ok(None),
        }
    }

    pub const fn is_proxy_handshaking(&self) -> bool {
        match self {
            Self::Proxied { stream } => stream.is_handshaking(),
            Self::NotProxied { .. } => false,
        }
    }
}

impl<S> Deref for MaybeProxyStream<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Proxied { stream } => &**stream,
            Self::NotProxied { stream } => stream,
        }
    }
}

impl<S> AsyncRead for MaybeProxyStream<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeProxyStreamProj::Proxied { stream } => stream.poll_read(cx, buf),
            MaybeProxyStreamProj::NotProxied { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for MaybeProxyStream<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            MaybeProxyStreamProj::Proxied { stream } => stream.poll_write(cx, buf),
            MaybeProxyStreamProj::NotProxied { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.project() {
            MaybeProxyStreamProj::Proxied { stream } => stream.poll_flush(cx),
            MaybeProxyStreamProj::NotProxied { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project() {
            MaybeProxyStreamProj::Proxied { stream } => stream.poll_shutdown(cx),
            MaybeProxyStreamProj::NotProxied { stream } => stream.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            MaybeProxyStreamProj::Proxied { stream } => stream.poll_write_vectored(cx, bufs),
            MaybeProxyStreamProj::NotProxied { stream } => stream.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeProxyStream::Proxied { stream } => stream.is_write_vectored(),
            MaybeProxyStream::NotProxied { stream } => stream.is_write_vectored(),
        }
    }
}
