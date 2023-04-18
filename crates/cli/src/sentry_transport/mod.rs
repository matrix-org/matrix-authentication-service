// Copyright 2023 The Matrix.org Foundation C.I.C.
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

//! Implements a transport for Sentry based on Hyper.
//!
//! This avoids the dependency on `reqwest`, which helps avoiding having two
//! HTTP and TLS stacks in the binary.
//!
//! The [`ratelimit`] and [`tokio_thread`] modules are directly copied from the
//! Sentry codebase.

use std::{sync::Arc, time::Duration};

use hyper::{client::connect::Connect, header::RETRY_AFTER, Client, StatusCode};
use sentry::{sentry_debug, ClientOptions, Transport, TransportFactory};

use self::tokio_thread::TransportThread;

mod ratelimit;
mod tokio_thread;

pub struct HyperTransport {
    thread: TransportThread,
}

pub struct HyperTransportFactory<C> {
    client: Client<C>,
}

impl<C> HyperTransportFactory<C> {
    pub fn new(client: Client<C>) -> Self {
        Self { client }
    }
}

impl<C> TransportFactory for HyperTransportFactory<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    fn create_transport(&self, options: &ClientOptions) -> Arc<dyn Transport> {
        Arc::new(HyperTransport::new(options, self.client.clone()))
    }
}

impl HyperTransport {
    pub fn new<C>(options: &ClientOptions, client: Client<C>) -> Self
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let dsn = options.dsn.as_ref().unwrap();
        let user_agent = options.user_agent.clone();
        let auth = dsn.to_auth(Some(&user_agent)).to_string();
        let url = dsn.envelope_api_url().to_string();

        let thread = TransportThread::new(move |envelope, mut rl| {
            let mut body = Vec::new();
            envelope.to_writer(&mut body).unwrap();

            let request = hyper::Request::post(&url)
                .header("X-Sentry-Auth", &auth)
                .body(hyper::Body::from(body))
                .unwrap();

            let fut = client.request(request);

            async move {
                match fut.await {
                    Ok(response) => {
                        if let Some(sentry_header) = response
                            .headers()
                            .get("x-sentry-rate-limits")
                            .and_then(|x| x.to_str().ok())
                        {
                            rl.update_from_sentry_header(sentry_header);
                        } else if let Some(retry_after) = response
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|x| x.to_str().ok())
                        {
                            rl.update_from_retry_after(retry_after);
                        } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
                            rl.update_from_429();
                        }

                        match hyper::body::to_bytes(response.into_body()).await {
                            Err(err) => {
                                sentry_debug!("Failed to read sentry response: {}", err);
                            }
                            Ok(bytes) => {
                                let text = String::from_utf8_lossy(&bytes);
                                sentry_debug!("Get response: `{}`", text);
                            }
                        }
                    }
                    Err(err) => {
                        sentry_debug!("Failed to send envelope: {}", err);
                    }
                }

                rl
            }
        });

        Self { thread }
    }
}

impl Transport for HyperTransport {
    fn send_envelope(&self, envelope: sentry::Envelope) {
        self.thread.send(envelope);
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.thread.flush(timeout)
    }

    fn shutdown(&self, timeout: Duration) -> bool {
        self.flush(timeout)
    }
}
