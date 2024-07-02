// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
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

use http_body_util::Full;
use hyper_util::rt::TokioExecutor;
use mas_http::{
    make_traced_connector, BodyToBytesResponseLayer, Client, ClientLayer, ClientService,
    HttpService, TracedClient, TracedConnector,
};
use tower::{
    util::{MapErrLayer, MapRequestLayer},
    BoxError, Layer,
};

#[derive(Debug, Clone)]
pub struct HttpClientFactory {
    traced_connector: TracedConnector,
    client_layer: ClientLayer,
}

impl Default for HttpClientFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClientFactory {
    /// Constructs a new HTTP client factory
    #[must_use]
    pub fn new() -> Self {
        Self {
            traced_connector: make_traced_connector(),
            client_layer: ClientLayer::new(),
        }
    }

    /// Constructs a new HTTP client
    pub fn client<B>(&self, category: &'static str) -> ClientService<TracedClient<B>>
    where
        B: axum::body::HttpBody + Send,
        B::Data: Send,
    {
        let client = Client::builder(TokioExecutor::new()).build(self.traced_connector.clone());
        self.client_layer
            .clone()
            .with_category(category)
            .layer(client)
    }

    /// Constructs a new [`HttpService`], suitable for `mas-oidc-client`
    pub fn http_service(&self, category: &'static str) -> HttpService {
        let client = self.client(category);
        let client = (
            MapErrLayer::new(BoxError::from),
            MapRequestLayer::new(|req: http::Request<_>| req.map(Full::new)),
            BodyToBytesResponseLayer,
        )
            .layer(client);

        HttpService::new(client)
    }
}
