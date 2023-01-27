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

use std::sync::Arc;

use futures_util::{Stream, StreamExt};
use http_body::Body;
use hyper::{Request, Response};
use thiserror::Error;
use tokio_rustls::rustls::ServerConfig;
use tower_http::add_extension::AddExtension;
use tower_service::Service;

use crate::{
    maybe_tls::{MaybeTlsAcceptor, TlsStreamInfo},
    proxy_protocol::{MaybeProxyAcceptor, ProxyAcceptError},
    unix_or_tcp::{SocketAddr, UnixOrTcpConnection, UnixOrTcpListener},
    ConnectionInfo,
};

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
        S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
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

    #[error(transparent)]
    Hyper(#[from] hyper::Error),
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
}

async fn accept<S, B>(
    maybe_proxy_acceptor: &MaybeProxyAcceptor,
    maybe_tls_acceptor: &MaybeTlsAcceptor,
    peer_addr: SocketAddr,
    stream: UnixOrTcpConnection,
    service: S,
) -> Result<(), AcceptError>
where
    S: Service<Request<hyper::Body>, Response = Response<B>>,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
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

    if is_h2 {
        hyper::server::conn::Http::new()
            .http2_only(true)
            .serve_connection(stream, service)
            .with_upgrades()
            .await?;
    } else {
        hyper::server::conn::Http::new()
            .http1_only(true)
            .http1_keep_alive(false)
            .serve_connection(stream, service)
            .with_upgrades()
            .await?;
    };

    Ok(())
}

pub async fn run_servers<S, B, SD>(listeners: impl IntoIterator<Item = Server<S>>, mut shutdown: SD)
where
    S: Service<Request<hyper::Body>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    SD: Stream + Unpin,
    SD::Item: std::fmt::Display,
{
    let listeners: Vec<_> = listeners
        .into_iter()
        .map(|server| {
            let maybe_proxy_acceptor = MaybeProxyAcceptor::new(server.proxy);
            let maybe_tls_acceptor = MaybeTlsAcceptor::new(server.tls);
            let service = server.service;
            let listener = server.listener;
            (maybe_proxy_acceptor, maybe_tls_acceptor, service, listener)
        })
        .collect();

    let mut set = tokio::task::JoinSet::new();

    loop {
        let mut accept_all: futures_util::stream::FuturesUnordered<_> = listeners
            .iter()
            .map(
                |(maybe_proxy_acceptor, maybe_tls_acceptor, service, listener)| async move {
                    listener
                        .accept()
                        .await
                        .map_err(AcceptError::socket)
                        .map(|(addr, conn)| {
                            (
                                maybe_proxy_acceptor.clone(),
                                maybe_tls_acceptor.clone(),
                                service.clone(),
                                addr,
                                conn,
                            )
                        })
                },
            )
            .collect();

        tokio::select! {
            biased;

            // First look for the shutdown signal
            res = shutdown.next() => {
                let why = res.map_or_else(|| String::from("???"), |why| format!("{why}"));
                tracing::info!("Received shutdown signal ({why})");

                break;
            },

            // Poll on the JoinSet, clearing finished task
            res = set.join_next(), if !set.is_empty() => {
                match res {
                    Some(Ok(Ok(()))) => tracing::trace!("Task was successful"),
                    Some(Ok(Err(e))) => tracing::error!("{e}"),
                    Some(Err(e)) => tracing::error!("Join error: {e}"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Then look for connections to accept
            res = accept_all.next(), if !accept_all.is_empty() => {
                // SAFETY: We shouldn't reach this branch if the unordered future set is empty
                let res = if let Some(res) = res { res } else { unreachable!() };

                // Spawn the connection in the set, so we don't have to wait for the handshake to
                // accept the next connection. This allows us to keep track of active connections
                // and waiting on them for a graceful shutdown
                set.spawn(async move {
                    let (maybe_proxy_acceptor, maybe_tls_acceptor, service, peer_addr, stream) = res?;
                    accept(&maybe_proxy_acceptor, &maybe_tls_acceptor, peer_addr, stream, service).await
                });
            },
        };
    }

    if !set.is_empty() {
        tracing::info!(
            "There are {active} active connections, performing a graceful shutdown. Send the shutdown signal again to force.",
            active = set.len()
        );

        loop {
            tokio::select! {
                biased;

                res = set.join_next() => {
                    match res {
                        Some(Ok(Ok(()))) => tracing::trace!("Task was successful"),
                        Some(Ok(Err(e))) => tracing::error!("{e}"),
                        Some(Err(e)) => tracing::error!("Join error: {e}"),
                        // No more tasks, going out
                        None => break,
                    }
                },


                res = shutdown.next() => {
                    let why = res.map_or_else(|| String::from("???"), |why| format!("{why}"));
                    tracing::warn!("Received shutdown signal again ({why}), forcing shutdown ({active} active connections)", active = set.len());
                    break;
                },
            }
        }
    }

    set.shutdown().await;
    tracing::info!("Shutdown complete");
}
