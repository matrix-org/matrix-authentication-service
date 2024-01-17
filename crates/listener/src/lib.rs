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

#![deny(rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]

//! An utility crate to build flexible [`hyper`] listeners, with optional TLS
//! and proxy protocol support.

use self::{maybe_tls::TlsStreamInfo, proxy_protocol::ProxyProtocolV1Info};

pub mod maybe_tls;
pub mod proxy_protocol;
pub mod rewind;
pub mod server;
pub mod shutdown;
pub mod unix_or_tcp;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    tls: Option<TlsStreamInfo>,
    proxy: Option<ProxyProtocolV1Info>,
    net_peer_addr: Option<std::net::SocketAddr>,
}

impl ConnectionInfo {
    /// Returns informations about the TLS connection. Returns [`None`] if the
    /// connection was not TLS.
    #[must_use]
    pub fn get_tls_ref(&self) -> Option<&TlsStreamInfo> {
        self.tls.as_ref()
    }

    /// Returns informations about the proxy protocol connection. Returns
    /// [`None`] if the connection was not using the proxy protocol.
    #[must_use]
    pub fn get_proxy_ref(&self) -> Option<&ProxyProtocolV1Info> {
        self.proxy.as_ref()
    }

    /// Returns the remote peer address. Returns [`None`] if the connection was
    /// established via a UNIX domain socket.
    #[must_use]
    pub fn get_peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.net_peer_addr
    }
}
