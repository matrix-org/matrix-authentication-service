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

use clap::Parser;
use figment::Figment;
use hyper::{Response, Uri};
use mas_config::{ConfigurationSection, PolicyConfig};
use mas_handlers::HttpClientFactory;
use mas_http::HttpServiceExt;
use tokio::io::AsyncWriteExt;
use tower::{Service, ServiceExt};
use tracing::{info, info_span};

use crate::util::policy_factory_from_config;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Perform an HTTP request with the default HTTP client
    Http {
        /// Show response headers
        #[arg(long, short = 'I')]
        show_headers: bool,

        /// Parse the response as JSON
        #[arg(long, short = 'j')]
        json: bool,

        /// URI where to perform a GET request
        url: Uri,
    },

    /// Check that the policies compile
    Policy,
}

fn print_headers(parts: &hyper::http::response::Parts) {
    println!(
        "{:?} {} {}",
        parts.version,
        parts.status.as_str(),
        parts.status.canonical_reason().unwrap_or_default()
    );

    for (header, value) in &parts.headers {
        println!("{header}: {value:?}");
    }
    println!();
}

impl Options {
    #[tracing::instrument(skip_all)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<()> {
        use Subcommand as SC;
        let http_client_factory = HttpClientFactory::new();
        match self.subcommand {
            SC::Http {
                show_headers,
                json: false,
                url,
            } => {
                let _span = info_span!("cli.debug.http").entered();
                let mut client = http_client_factory.client("debug");
                let request = hyper::Request::builder()
                    .uri(url)
                    .body(hyper::Body::empty())?;

                let response = client.ready().await?.call(request).await?;
                let (parts, body) = response.into_parts();

                if show_headers {
                    print_headers(&parts);
                }

                let mut body = hyper::body::aggregate(body).await?;
                let mut stdout = tokio::io::stdout();
                stdout.write_all_buf(&mut body).await?;
            }

            SC::Http {
                show_headers,
                json: true,
                url,
            } => {
                let _span = info_span!("cli.debug.http").entered();
                let mut client = http_client_factory
                    .client("debug")
                    .response_body_to_bytes()
                    .json_response();
                let request = hyper::Request::builder()
                    .uri(url)
                    .body(hyper::Body::empty())?;

                let response: Response<serde_json::Value> =
                    client.ready().await?.call(request).await?;
                let (parts, body) = response.into_parts();

                if show_headers {
                    print_headers(&parts);
                }

                let body = serde_json::to_string_pretty(&body)?;
                println!("{body}");
            }

            SC::Policy => {
                let _span = info_span!("cli.debug.policy").entered();
                let config = PolicyConfig::extract(figment)?;
                info!("Loading and compiling the policy module");
                let policy_factory = policy_factory_from_config(&config).await?;

                let _instance = policy_factory.instantiate().await?;
            }
        }

        Ok(())
    }
}
