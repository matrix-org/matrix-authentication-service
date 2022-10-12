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

use tokio::io::AsyncRead;

use super::{acceptor::ProxyAcceptError, ProxyAcceptor, ProxyProtocolV1Info};
use crate::rewind::Rewind;

#[derive(Clone)]
pub struct MaybeProxyAcceptor {
    acceptor: Option<ProxyAcceptor>,
}

impl MaybeProxyAcceptor {
    #[must_use]
    pub const fn new(proxied: bool) -> Self {
        let acceptor = if proxied {
            Some(ProxyAcceptor::new())
        } else {
            None
        };

        Self { acceptor }
    }

    #[must_use]
    pub const fn new_proxied(acceptor: ProxyAcceptor) -> Self {
        Self {
            acceptor: Some(acceptor),
        }
    }

    #[must_use]
    pub const fn new_unproxied() -> Self {
        Self { acceptor: None }
    }

    #[must_use]
    pub const fn is_proxied(&self) -> bool {
        self.acceptor.is_some()
    }

    /// Accept a connection and do the proxy protocol handshake
    ///
    /// # Errors
    ///
    /// Returns an error if the proxy protocol handshake failed
    pub async fn accept<T>(
        &self,
        stream: T,
    ) -> Result<(Option<ProxyProtocolV1Info>, Rewind<T>), ProxyAcceptError>
    where
        T: AsyncRead + Unpin,
    {
        match &self.acceptor {
            Some(acceptor) => {
                let (info, stream) = acceptor.accept(stream).await?;
                Ok((Some(info), stream))
            }
            None => {
                let stream = Rewind::new(stream);
                Ok((None, stream))
            }
        }
    }
}
