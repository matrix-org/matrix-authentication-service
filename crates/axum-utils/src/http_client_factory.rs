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

use axum::body::Full;
use mas_http::{
    BodyToBytesResponseLayer, ClientInitError, ClientLayer, ClientService, HttpService,
    TracedClient,
};
use tokio::sync::Semaphore;
use tower::{
    util::{MapErrLayer, MapRequestLayer},
    BoxError, Layer,
};

#[derive(Debug, Clone)]
pub struct HttpClientFactory {
    semaphore: Arc<Semaphore>,
}

impl HttpClientFactory {
    #[must_use]
    pub fn new(concurrency_limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency_limit)),
        }
    }

    /// Constructs a new HTTP client
    ///
    /// # Errors
    ///
    /// Returns an error if the client failed to initialise
    pub async fn client<B>(
        &self,
        operation: &'static str,
    ) -> Result<ClientService<TracedClient<B>>, ClientInitError>
    where
        B: axum::body::HttpBody + Send + Sync + 'static,
        B::Data: Send,
    {
        let client = mas_http::make_traced_client::<B>().await?;
        let layer = ClientLayer::with_semaphore(operation, self.semaphore.clone());
        Ok(layer.layer(client))
    }

    /// Constructs a new [`HttpService`], suitable for `mas-oidc-client`
    ///
    /// # Errors
    ///
    /// Returns an error if the client failed to initialise
    pub async fn http_service(
        &self,
        operation: &'static str,
    ) -> Result<HttpService, ClientInitError> {
        let client = self.client(operation).await?;
        let client = (
            MapErrLayer::new(BoxError::from),
            MapRequestLayer::new(|req: http::Request<_>| req.map(Full::new)),
            BodyToBytesResponseLayer::default(),
        )
            .layer(client);

        Ok(HttpService::new(client))
    }
}
