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

use std::{
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::{ready, Future};
use hyper::server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::{ServerConfig, ServerConnection};

pub enum MaybeTlsStream<T> {
    Handshaking(tokio_rustls::Accept<T>),
    Streaming(tokio_rustls::server::TlsStream<T>),
    Insecure(T),
}

impl<T> MaybeTlsStream<T> {
    pub fn new(stream: T, config: Option<Arc<ServerConfig>>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(config) = config {
            let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
            MaybeTlsStream::Handshaking(accept)
        } else {
            MaybeTlsStream::Insecure(stream)
        }
    }

    /// Get a reference to the underlying IO stream
    ///
    /// Returns [`None`] if the stream closed before the TLS handshake finished.
    /// It is guaranteed to return [`Some`] value after the handshake finished,
    /// or if it is a non-TLS connection.
    pub fn get_ref(&self) -> Option<&T> {
        match self {
            Self::Handshaking(accept) => accept.get_ref(),
            Self::Streaming(stream) => {
                let (inner, _) = stream.get_ref();
                Some(inner)
            }
            Self::Insecure(inner) => Some(inner),
        }
    }

    /// Get a ref to the [`ServerConnection`] of the establish TLS stream.
    ///
    /// Returns [`None`] if the connection is still handshaking and for non-TLS
    /// connections.
    pub fn get_tls_connection(&self) -> Option<&ServerConnection> {
        match self {
            Self::Streaming(stream) => {
                let (_, conn) = stream.get_ref();
                Some(conn)
            }
            Self::Handshaking(_) | Self::Insecure(_) => None,
        }
    }
}

impl<T> AsyncRead for MaybeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        match pin {
            MaybeTlsStream::Handshaking(ref mut accept) => {
                match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_read(cx, buf);
                        *pin = MaybeTlsStream::Streaming(stream);
                        result
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            MaybeTlsStream::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
            MaybeTlsStream::Insecure(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let pin = self.get_mut();
        match pin {
            MaybeTlsStream::Handshaking(ref mut accept) => {
                match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_write(cx, buf);
                        *pin = MaybeTlsStream::Streaming(stream);
                        result
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            MaybeTlsStream::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
            MaybeTlsStream::Insecure(ref mut fallback) => Pin::new(fallback).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Handshaking { .. } => Poll::Ready(Ok(())),
            MaybeTlsStream::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
            MaybeTlsStream::Insecure(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Handshaking { .. } => Poll::Ready(Ok(())),
            MaybeTlsStream::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeTlsStream::Insecure(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct MaybeTlsAcceptor<T> {
    tls_config: Option<Arc<ServerConfig>>,
    incoming: T,
}

impl<T> MaybeTlsAcceptor<T> {
    pub fn new(tls_config: Option<Arc<ServerConfig>>, incoming: T) -> Self {
        Self {
            tls_config,
            incoming,
        }
    }

    pub fn new_secure(tls_config: Arc<ServerConfig>, incoming: T) -> Self {
        Self {
            tls_config: Some(tls_config),
            incoming,
        }
    }

    pub fn new_insecure(incoming: T) -> Self {
        Self {
            tls_config: None,
            incoming,
        }
    }

    pub const fn is_secure(&self) -> bool {
        self.tls_config.is_some()
    }
}

impl<T> Accept for MaybeTlsAcceptor<T>
where
    T: Accept + Unpin,
    T::Conn: AsyncRead + AsyncWrite + Unpin,
    T::Error: Into<std::io::Error>,
{
    type Conn = MaybeTlsStream<T::Conn>;
    type Error = std::io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();

        let ret = match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => {
                let config = pin.tls_config.clone();
                Some(Ok(MaybeTlsStream::new(sock, config)))
            }

            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        };

        Poll::Ready(ret)
    }
}

impl<T> Deref for MaybeTlsAcceptor<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.incoming
    }
}
