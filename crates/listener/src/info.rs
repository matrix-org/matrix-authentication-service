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
    future::Ready,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use hyper::server::accept::Accept;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::OnceCell,
};
use tower::Service;
use tower_http::add_extension::AddExtension;

use crate::{
    maybe_tls::{MaybeTlsAcceptor, MaybeTlsStream, TlsStreamInfo, TlsStreamInfoError},
    proxy_protocol::{
        MaybeProxyAcceptor, MaybeProxyStream, ProxyHandshakeNotDone, ProxyProtocolV1Info,
    },
    unix_or_tcp::{UnixOrTcpConnection, UnixOrTcpListener},
};

// TODO: this is a mess, clean that up

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FromStreamError {
    #[error(transparent)]
    Proxy(#[from] ProxyHandshakeNotDone),

    #[error(transparent)]
    Tls(#[from] TlsStreamInfoError),

    #[error("Could not grab a reference to the underlying stream")]
    GetRef,

    #[error("Could not get address info from underlying stream")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Connection {
    proxy: Option<ProxyProtocolV1Info>,
    tls: Option<TlsStreamInfo>,

    // We're not saving the UNIX domain socket address here because it can't be cloned, which is
    // required for injecting the connection information as an extension
    local_tcp_addr: Option<SocketAddr>,
    peer_tcp_addr: Option<SocketAddr>,
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum GrabAddressError {
    #[error("Proxy protocol was initiated with an unknown protocol")]
    ProxyUnknown,

    #[error("Proxy protocol was initiated with UDP")]
    ProxyUdp,

    #[error("Underlying listener is a UNIX socket")]
    UnixListener,
}

impl MaybeProxyAcceptor<MaybeTlsAcceptor<UnixOrTcpListener>> {
    pub fn can_have_peer_address(&self) -> bool {
        self.is_proxied() || self.is_tcp()
    }
}

impl MaybeProxyStream<MaybeTlsStream<UnixOrTcpConnection>> {
    /// Get informations about this connection
    ///
    /// # Errors
    ///
    /// Returns an error if the proxy protocol or the TLS handhakes are not done
    /// yet
    pub fn connection_info(&self) -> Result<Connection, FromStreamError> {
        Connection::from_stream(self)
    }
}

impl Connection {
    /// Get informations about this connection
    ///
    /// # Errors
    ///
    /// Returns an error if the proxy protocol or the TLS handhakes are not done
    /// yet
    pub fn from_stream(
        stream: &MaybeProxyStream<MaybeTlsStream<UnixOrTcpConnection>>,
    ) -> Result<Self, FromStreamError> {
        let proxy = stream.proxy_info()?.cloned();
        let tls = stream.tls_info()?;
        let original = stream.get_ref().ok_or(FromStreamError::GetRef)?;
        let local_tcp_addr = original.local_addr()?.into_net();
        let peer_tcp_addr = original.peer_addr()?.into_net();

        Ok(Self {
            proxy,
            tls,
            local_tcp_addr,
            peer_tcp_addr,
        })
    }

    #[must_use]
    pub const fn is_proxied(&self) -> bool {
        self.proxy.is_some()
    }

    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Get the outmost peer address, either from the TCP listener or from the
    /// proxy protocol infos.
    ///
    /// # Errors
    ///
    /// Returns an error if the info from the proxy protocol was not for a TCP
    /// connection, or if the proxy protocol is not being used, the underlying
    /// listener was a UNIX domain socket
    pub fn peer_addr(&self) -> Result<&SocketAddr, GrabAddressError> {
        if let Some(proxy) = self.proxy.as_ref() {
            if proxy.is_udp() {
                return Err(GrabAddressError::ProxyUdp);
            }

            proxy.source().ok_or(GrabAddressError::ProxyUnknown)
        } else {
            self.peer_tcp_addr
                .as_ref()
                .ok_or(GrabAddressError::UnixListener)
        }
    }

    /// Get the outmost local address, either from the TCP listener or from the
    /// proxy protocol infos.
    ///
    /// # Errors
    ///
    /// Returns an error if the info from the proxy protocol was not for a TCP
    /// connection, or if the proxy protocol is not being used, the underlying
    /// listener was a UNIX domain socket
    pub fn local_addr(&self) -> Result<&SocketAddr, GrabAddressError> {
        if let Some(proxy) = self.proxy.as_ref() {
            if proxy.is_udp() {
                return Err(GrabAddressError::ProxyUdp);
            }

            proxy.destination().ok_or(GrabAddressError::ProxyUnknown)
        } else {
            self.local_tcp_addr
                .as_ref()
                .ok_or(GrabAddressError::UnixListener)
        }
    }
}

pin_project_lite::pin_project! {
    pub struct ConnectionInfoAcceptor {
        #[pin]
        acceptor: MaybeProxyAcceptor<MaybeTlsAcceptor<UnixOrTcpListener>>,
    }
}

impl ConnectionInfoAcceptor {
    pub const fn new(acceptor: MaybeProxyAcceptor<MaybeTlsAcceptor<UnixOrTcpListener>>) -> Self {
        Self { acceptor }
    }
}

impl Accept for ConnectionInfoAcceptor {
    type Conn = ConnectionInfoStream;
    type Error = std::io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let proj = self.project();
        let ret = match futures_util::ready!(proj.acceptor.poll_accept(cx)) {
            Some(Ok(conn)) => Some(Ok(ConnectionInfoStream::new(conn))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        };
        Poll::Ready(ret)
    }
}

pin_project_lite::pin_project! {
    pub struct ConnectionInfoStream {
        connection: Arc<OnceCell<Connection>>,
        #[pin]
        stream: MaybeProxyStream<MaybeTlsStream<UnixOrTcpConnection>>,
    }
}

impl ConnectionInfoStream {
    pub fn new(stream: MaybeProxyStream<MaybeTlsStream<UnixOrTcpConnection>>) -> Self {
        Self {
            connection: Arc::new(OnceCell::const_new()),
            stream,
        }
    }
}

impl Deref for ConnectionInfoStream {
    type Target = MaybeProxyStream<MaybeTlsStream<UnixOrTcpConnection>>;
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl AsyncRead for ConnectionInfoStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        futures_util::ready!(Pin::new(&mut this.stream).poll_read(cx, buf))?;

        if !this.stream.is_tls_handshaking()
            && !this.stream.is_proxy_handshaking()
            && !this.connection.initialized()
        {
            this.connection
                .set(this.stream.connection_info().unwrap())
                .unwrap();
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ConnectionInfoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let proj = self.project();
        proj.stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let proj = self.project();
        proj.stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let proj = self.project();
        proj.stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let proj = self.project();
        proj.stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[derive(Debug, Clone)]
pub struct IntoMakeServiceWithConnection<S> {
    svc: S,
}

impl<S> IntoMakeServiceWithConnection<S> {
    pub const fn new(svc: S) -> Self {
        Self { svc }
    }
}

impl<S> Service<&ConnectionInfoStream> for IntoMakeServiceWithConnection<S>
where
    S: Clone,
{
    type Response = AddExtension<S, Arc<OnceCell<Connection>>>;
    type Error = FromStreamError;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: &ConnectionInfoStream) -> Self::Future {
        std::future::ready(Ok(AddExtension::new(
            self.svc.clone(),
            target.connection.clone(),
        )))
    }
}
