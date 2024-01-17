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
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
    time::Duration,
};

use event_listener::{Event, EventListener};
use futures_util::{stream::SelectAll, Stream, StreamExt};
use http_body::Body;
use hyper::{body::HttpBody, server::conn::Connection, Request, Response};
use pin_project_lite::pin_project;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::ServerConfig;
use tower_http::add_extension::AddExtension;
use tower_service::Service;
use tracing::Instrument;

use crate::{
    maybe_tls::{MaybeTlsAcceptor, MaybeTlsStream, TlsStreamInfo},
    proxy_protocol::{MaybeProxyAcceptor, ProxyAcceptError},
    rewind::Rewind,
    unix_or_tcp::{SocketAddr, UnixOrTcpConnection, UnixOrTcpListener},
    ConnectionInfo,
};

/// The timeout for the handshake to complete
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Server<S> {
    tls: Option<Arc<ServerConfig>>,
    proxy: bool,
    listener: UnixOrTcpListener,
    service: S,
}

impl<S> Server<S> {
    /// # Errors
    ///
    /// Returns an error if the listener couldn't be converted via [`TryInto`]
    pub fn try_new<L>(listener: L, service: S) -> Result<Self, L::Error>
    where
        L: TryInto<UnixOrTcpListener>,
    {
        Ok(Self {
            tls: None,
            proxy: false,
            listener: listener.try_into()?,
            service,
        })
    }

    #[must_use]
    pub fn new(listener: impl Into<UnixOrTcpListener>, service: S) -> Self {
        Self {
            tls: None,
            proxy: false,
            listener: listener.into(),
            service,
        }
    }

    #[must_use]
    pub const fn with_proxy(mut self) -> Self {
        self.proxy = true;
        self
    }

    #[must_use]
    pub fn with_tls(mut self, config: Arc<ServerConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// Run a single server
    pub async fn run<B, SD>(self, shutdown: SD)
    where
        S: Service<Request<hyper::Body>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: std::error::Error + Send + Sync + 'static,
        SD: Stream + Unpin,
        SD::Item: std::fmt::Display,
    {
        run_servers(std::iter::once(self), shutdown).await;
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
enum AcceptError {
    #[error("failed to accept connection from the underlying socket")]
    Socket {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to complete the TLS handshake")]
    TlsHandshake {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to complete the proxy protocol handshake")]
    ProxyHandshake {
        #[source]
        source: ProxyAcceptError,
    },

    #[error("connection handshake timed out")]
    HandshakeTimeout {
        #[source]
        source: tokio::time::error::Elapsed,
    },
}

impl AcceptError {
    fn socket(source: std::io::Error) -> Self {
        Self::Socket { source }
    }

    fn tls_handshake(source: std::io::Error) -> Self {
        Self::TlsHandshake { source }
    }

    fn proxy_handshake(source: ProxyAcceptError) -> Self {
        Self::ProxyHandshake { source }
    }

    fn handshake_timeout(source: tokio::time::error::Elapsed) -> Self {
        Self::HandshakeTimeout { source }
    }
}

/// Accept a connection and do the proxy protocol and TLS handshake
///
/// Returns an error if the proxy protocol or TLS handshake failed.
/// Returns the connection, which should be used to spawn a task to serve the
/// connection.
#[allow(clippy::type_complexity)]
#[tracing::instrument(
    name = "accept",
    skip_all,
    fields(
        network.protocol.name = "http",
        network.peer.address,
        network.peer.port,
    ),
    err,
)]
async fn accept<S, B>(
    maybe_proxy_acceptor: &MaybeProxyAcceptor,
    maybe_tls_acceptor: &MaybeTlsAcceptor,
    peer_addr: SocketAddr,
    stream: UnixOrTcpConnection,
    service: S,
) -> Result<
    Connection<MaybeTlsStream<Rewind<UnixOrTcpConnection>>, AddExtension<S, ConnectionInfo>>,
    AcceptError,
>
where
    S: Service<Request<hyper::Body>, Response = Response<B>>,
    S::Error: std::error::Error + Send + Sync + 'static,
    S::Future: Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let span = tracing::Span::current();

    match peer_addr {
        SocketAddr::Net(addr) => {
            span.record("network.peer.address", tracing::field::display(addr.ip()));
            span.record("network.peer.port", addr.port());
        }
        SocketAddr::Unix(ref addr) => {
            span.record("network.peer.address", tracing::field::debug(addr));
        }
    }

    // Wrap the connection acceptation logic in a timeout
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let (proxy, stream) = maybe_proxy_acceptor
            .accept(stream)
            .await
            .map_err(AcceptError::proxy_handshake)?;

        let stream = maybe_tls_acceptor
            .accept(stream)
            .await
            .map_err(AcceptError::tls_handshake)?;

        let tls = stream.tls_info();

        // Figure out if it's HTTP/2 based on the negociated ALPN info
        let is_h2 = tls.as_ref().map_or(false, TlsStreamInfo::is_alpn_h2);

        let info = ConnectionInfo {
            tls,
            proxy,
            net_peer_addr: peer_addr.into_net(),
        };

        let service = AddExtension::new(service, info);

        let conn = if is_h2 {
            hyper::server::conn::Http::new()
                .http2_only(true)
                .serve_connection(stream, service)
        } else {
            hyper::server::conn::Http::new()
                .http1_only(true)
                .http1_keep_alive(true)
                .serve_connection(stream, service)
        };

        Ok(conn)
    })
    .instrument(span)
    .await
    .map_err(AcceptError::handshake_timeout)?
}

pin_project! {
    /// A wrapper around a connection that can be aborted when a shutdown signal is received.
    ///
    /// This works by sharing an atomic boolean between all connections, and when a shutdown
    /// signal is received, the boolean is set to true. The connection will then check the
    /// boolean before polling the underlying connection, and if it's true, it will start a
    /// graceful shutdown.
    ///
    /// We also use an event listener to wake up the connection when the shutdown signal is
    /// received, because the connection needs to be polled again to start the graceful shutdown.
    struct AbortableConnection<C> {
        #[pin]
        connection: C,
        #[pin]
        shutdown_listener: EventListener,
        shutdown_event: Arc<Event>,
        shutdown_in_progress: Arc<AtomicBool>,
        did_start_shutdown: bool,
    }
}

impl<C> AbortableConnection<C> {
    fn new(connection: C, shutdown_in_progress: &Arc<AtomicBool>, event: &Arc<Event>) -> Self {
        let shutdown_listener = EventListener::new();
        Self {
            connection,
            shutdown_listener,
            shutdown_in_progress: Arc::clone(shutdown_in_progress),
            shutdown_event: Arc::clone(event),
            did_start_shutdown: false,
        }
    }
}

impl<T, S, B> Future for AbortableConnection<Connection<T, S>>
where
    Connection<T, S>: Future,
    S: Service<Request<hyper::Body>, Response = Response<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::error::Error + Send + Sync,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = <Connection<T, S> as Future>::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        // If we aren't listening for the shutdown signal, start listening
        if !this.shutdown_listener.is_listening() {
            // XXX: it feels like we should setup the listener when we create it, but it
            // needs a `Pin<&mut EventListener>` to do so, and I can't figure out
            // how to get one outside of the `poll` method.
            this.shutdown_listener.as_mut().listen(this.shutdown_event);
        }

        // Poll the shutdown signal, so that wakers get registered.
        // XXX: I don't think we care about the result of this poll, since it's only
        // really to register wakers. But I'm not sure if it's safe to
        // ignore the result.
        let _ = this.shutdown_listener.poll(cx);

        if !*this.did_start_shutdown
            && this
                .shutdown_in_progress
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            *this.did_start_shutdown = true;
            this.connection.as_mut().graceful_shutdown();
        }

        this.connection.poll(cx)
    }
}

#[allow(clippy::too_many_lines)]
pub async fn run_servers<S, B, SD>(listeners: impl IntoIterator<Item = Server<S>>, mut shutdown: SD)
where
    S: Service<Request<hyper::Body>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
    SD: Stream + Unpin,
    SD::Item: std::fmt::Display,
{
    // Create a stream of accepted connections out of the listeners
    let mut accept_stream: SelectAll<_> = listeners
        .into_iter()
        .map(|server| {
            let maybe_proxy_acceptor = MaybeProxyAcceptor::new(server.proxy);
            let maybe_tls_acceptor = MaybeTlsAcceptor::new(server.tls);
            futures_util::stream::poll_fn(move |cx| {
                let res =
                    std::task::ready!(server.listener.poll_accept(cx)).map(|(addr, stream)| {
                        (
                            maybe_proxy_acceptor,
                            maybe_tls_acceptor.clone(),
                            server.service.clone(),
                            addr,
                            stream,
                        )
                    });
                Poll::Ready(Some(res))
            })
        })
        .collect();

    // A JoinSet which collects connections that are being accepted
    let mut accept_tasks = tokio::task::JoinSet::new();
    // A JoinSet which collects connections that are being served
    let mut connection_tasks = tokio::task::JoinSet::new();

    // A shared atomic boolean to tell all connections to shutdown
    let shutdown_in_progress = Arc::new(AtomicBool::new(false));
    let shutdown_event = Arc::new(Event::new());

    loop {
        tokio::select! {
            biased;

            // First look for the shutdown signal
            res = shutdown.next() => {
                let why = res.map_or_else(|| String::from("???"), |why| format!("{why}"));
                tracing::info!("Received shutdown signal ({why})");

                break;
            },

            // Poll on the JoinSet to collect connections to serve
            res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                match res {
                    Some(Ok(Ok(connection))) => {
                        tracing::trace!("Accepted connection");
                        let conn = AbortableConnection::new(connection, &shutdown_in_progress, &shutdown_event);
                        connection_tasks.spawn(conn);
                    },
                    Some(Ok(Err(_e))) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                    Some(Err(e)) => tracing::error!("Join error: {e}"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Poll on the JoinSet to collect finished connections
            res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                match res {
                    Some(Ok(Ok(()))) => tracing::trace!("Connection finished"),
                    Some(Ok(Err(e))) => tracing::error!("Error while serving connection: {e}"),
                    Some(Err(e)) => tracing::error!("Join error: {e}"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Look for connections to accept
            res = accept_stream.next(), if !accept_stream.is_empty() => {
                // SAFETY: We shouldn't reach this branch if the stream set is empty
                let Some(res) = res else { unreachable!() };

                // Spawn the connection in the set, so we don't have to wait for the handshake to
                // accept the next connection. This allows us to keep track of active connections
                // and waiting on them for a graceful shutdown
                accept_tasks.spawn(async move {
                    let (maybe_proxy_acceptor, maybe_tls_acceptor, service, peer_addr, stream) = res
                        .map_err(AcceptError::socket)?;
                    accept(&maybe_proxy_acceptor, &maybe_tls_acceptor, peer_addr, stream, service).await
                });
            },
        };
    }

    // Tell the active connections to shutdown
    shutdown_in_progress.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown_event.notify(usize::MAX);

    // Wait for connections to cleanup
    if !accept_tasks.is_empty() || !connection_tasks.is_empty() {
        tracing::info!(
            "There are {active} active connections ({pending} pending), performing a graceful shutdown. Send the shutdown signal again to force.",
            active = connection_tasks.len(),
            pending = accept_tasks.len(),
        );

        while !accept_tasks.is_empty() || !connection_tasks.is_empty() {
            tokio::select! {
                biased;

                // Poll on the JoinSet to collect connections to serve
                res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                    match res {
                        Some(Ok(Ok(connection))) => {
                            tracing::trace!("Accepted connection");
                            let conn = AbortableConnection::new(connection, &shutdown_in_progress, &shutdown_event);
                            connection_tasks.spawn(conn);
                        }
                        Some(Ok(Err(_e))) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                        Some(Err(e)) => tracing::error!("Join error: {e}"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Poll on the JoinSet to collect finished connections
                res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                    match res {
                        Some(Ok(Ok(()))) => tracing::trace!("Connection finished"),
                        Some(Ok(Err(e))) => tracing::error!("Error while serving connection: {e}"),
                        Some(Err(e)) => tracing::error!("Join error: {e}"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Handle when we receive the shutdown signal again
                res = shutdown.next() => {
                    let why = res.map_or_else(|| String::from("???"), |why| format!("{why}"));
                    tracing::warn!(
                        "Received shutdown signal again ({why}), forcing shutdown ({active} active connections, {pending} pending connections)",
                        active = connection_tasks.len(),
                        pending = accept_tasks.len(),
                    );
                    break;
                },
            }
        }
    }

    accept_tasks.shutdown().await;
    connection_tasks.shutdown().await;
    tracing::info!("Shutdown complete");
}
