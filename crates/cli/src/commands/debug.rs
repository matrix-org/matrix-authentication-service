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

use anyhow::Context;
use clap::Parser;
use hyper::{Response, Uri};
use mas_config::PolicyConfig;
use mas_http::HttpServiceExt;
use mas_policy::PolicyFactory;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tower::{Service, ServiceExt};
use tracing::info;

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
        println!("{}: {:?}", header, value);
    }
    println!();
}

impl Options {
    #[tracing::instrument(skip_all)]
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        match &self.subcommand {
            SC::Http {
                show_headers,
                json: false,
                url,
            } => {
                let mut client = mas_http::client("cli-debug-http").await?;
                let request = hyper::Request::builder()
                    .uri(url)
                    .body(hyper::Body::empty())?;

                let response = client.ready().await?.call(request).await?;
                let (parts, body) = response.into_parts();

                if *show_headers {
                    print_headers(&parts);
                }

                let mut body = hyper::body::aggregate(body).await?;
                let mut stdout = tokio::io::stdout();
                stdout.write_all_buf(&mut body).await?;

                Ok(())
            }

            SC::Http {
                show_headers,
                json: true,
                url,
            } => {
                let mut client = mas_http::client("cli-debug-http")
                    .await?
                    .response_body_to_bytes()
                    .json_response();
                let request = hyper::Request::builder()
                    .uri(url)
                    .body(hyper::Body::empty())?;

                let response: Response<serde_json::Value> =
                    client.ready().await?.call(request).await?;
                let (parts, body) = response.into_parts();

                if *show_headers {
                    print_headers(&parts);
                }

                let body = serde_json::to_string_pretty(&body)?;
                println!("{}", body);

                Ok(())
            }

            SC::Policy => {
                let config: PolicyConfig = root.load_config()?;
                info!("Loading and compiling the policy module");
                let mut policy: Box<dyn AsyncRead + std::marker::Unpin> =
                    if let Some(path) = &config.wasm_module {
                        Box::new(
                            tokio::fs::File::open(path)
                                .await
                                .context("failed to open OPA WASM policy file")?,
                        )
                    } else {
                        Box::new(mas_policy::default_wasm_policy())
                    };

                let policy_factory = PolicyFactory::load(
                    &mut policy,
                    config.data.clone().unwrap_or_default(),
                    config.register_entrypoint.clone(),
                    config.client_registration_entrypoint.clone(),
                    config.authorization_grant_entrypoint.clone(),
                )
                .await
                .context("failed to load the policy")?;

                let _instance = policy_factory.instantiate().await?;
                Ok(())
            }
        }
    }
}
