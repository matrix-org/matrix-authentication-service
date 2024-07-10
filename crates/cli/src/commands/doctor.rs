// Copyright 2024 The Matrix.org Foundation C.I.C.
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

//! Diagnostic utility to check the health of the deployment
//!
//! The code is quite repetitive for now, but we can refactor later with a
//! better check abstraction

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSection, RootConfig};
use mas_handlers::HttpClientFactory;
use mas_http::HttpServiceExt;
use tower::{Service, ServiceExt};
use tracing::{error, info, info_span, warn};
use url::{Host, Url};

/// Base URL for the human-readable documentation
const DOCS_BASE: &str = "https://matrix-org.github.io/matrix-authentication-service";

#[derive(Parser, Debug)]
pub(super) struct Options {}

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.doctor").entered();
        info!("💡 Running diagnostics, make sure that both MAS and Synapse are running, and that MAS is using the same configuration files as this tool.");

        let config = RootConfig::extract(figment)?;

        // We'll need an HTTP client
        let http_client_factory = HttpClientFactory::new();
        let base_url = config.http.public_base.as_str();
        let issuer = config.http.issuer.as_ref().map(url::Url::as_str);
        let issuer = issuer.unwrap_or(base_url);
        let matrix_domain: Host = Host::parse(&config.matrix.homeserver).context(
            r"The homeserver host in the config (`matrix.homeserver`) is not a valid domain.
See {DOCS_BASE}/setup/homeserver.html",
        )?;
        let hs_api = config.matrix.endpoint;
        let admin_token = config.matrix.secret;

        if !issuer.starts_with("https://") {
            warn!(
                r#"⚠️ The issuer in the config (`http.issuer`/`http.public_base`) is not an HTTPS URL.
This means some clients will refuse to use it."#
            );
        }

        let well_known_uri = format!("https://{matrix_domain}/.well-known/matrix/client");
        let mut client = http_client_factory
            .client("doctor")
            .response_body_to_bytes()
            .json_response::<serde_json::Value>();

        let request = hyper::Request::builder()
            .uri(&well_known_uri)
            .body(axum::body::Body::empty())?;
        let result = client.ready().await?.call(request).await;

        let expected_well_known = serde_json::json!({
            "m.homeserver": {
                "base_url": "...",
            },
            "org.matrix.msc2965.authentication": {
                "issuer": issuer,
                "account": format!("{base_url}account/"),
            },
        });

        let discovered_cs_api = match result {
            Ok(response) => {
                // Make sure we got a 2xx response
                let status = response.status();
                if !status.is_success() {
                    warn!(
                        r#"⚠️ Matrix client well-known replied with {status}, expected 2xx.
Make sure the homeserver is reachable and the well-known document is available at "{well_known_uri}""#,
                    );
                }

                let body = response.into_body();

                if let Some(auth) = body.get("org.matrix.msc2965.authentication") {
                    if let Some(wk_issuer) = auth.get("issuer").and_then(|issuer| issuer.as_str()) {
                        if issuer == wk_issuer {
                            info!(r#"✅ Matrix client well-known at "{well_known_uri}" is valid"#);
                        } else {
                            warn!(
                                r#"⚠️ Matrix client well-known has an "org.matrix.msc2965.authentication" section, but the issuer is not the same as the homeserver.
Check the well-known document at "{well_known_uri}"
This can happen because MAS parses the URL its config differently from the homeserver.
This means some OIDC-native clients might not work.
Make sure that the MAS config contains:

  http:
    public_base: {issuer:?}
    # Or, if the issuer is different from the public base:
    issuer: {issuer:?}

And in the Synapse config:

  experimental_features:
    msc3861:
      enabled: true
      # This must exactly match:
      issuer: {issuer:?}
      # ...

See {DOCS_BASE}/setup/homeserver.html
"#
                            );
                        }
                    } else {
                        error!(
                            r#"❌ Matrix client well-known "org.matrix.msc2965.authentication" does not have a valid "issuer" field.
Check the well-known document at "{well_known_uri}"
"#
                        );
                    }
                } else {
                    warn!(
                        r#"Matrix client well-known is missing the "org.matrix.msc2965.authentication" section.
Check the well-known document at "{well_known_uri}"
Make sure Synapse has delegated auth enabled:

  experimental_features:
    msc3861:
      enabled: true
      issuer: {issuer:?}
      # ...

If it is not Synapse handling the well-known document, update it to include the following:

{expected_well_known:#}

See {DOCS_BASE}/setup/homeserver.html
"#
                    );
                }

                // Return the discovered homeserver base URL
                body.get("m.homeserver")
                    .and_then(|hs| hs.get("base_url"))
                    .and_then(|base_url| base_url.as_str())
                    .and_then(|base_url| Url::parse(base_url).ok())
            }
            Err(e) => {
                warn!(
                    r#"⚠️ Failed to fetch well-known document at "{well_known_uri}".
This means that the homeserver is not reachable, the well-known document is not available, or malformed.
Make sure your homeserver is running.
Make sure going to {well_known_uri:?} in a web browser returns a valid JSON document, similar to:

{expected_well_known:#}

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
                );
                None
            }
        };

        // Now try to reach the homeserver
        let client_versions = hs_api.join("/_matrix/client/versions")?;
        let request = hyper::Request::builder()
            .uri(client_versions.as_str())
            .body(axum::body::Body::empty())?;
        let result = client.ready().await?.call(request).await;
        let can_reach_cs = match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(r#"✅ Homeserver is reachable at "{client_versions}""#);
                    true
                } else {
                    error!(
                        r#"❌Can't reach the homeserver at "{client_versions}", got {status}.
Make sure your homeserver is running.
This may be due to a misconfiguration in the `matrix` section of the config.

  matrix:
    homeserver: "{matrix_domain}"
    # The homeserver should be reachable at this URL
    endpoint: "{hs_api}"

See {DOCS_BASE}/setup/homeserver.html
"#
                    );
                    false
                }
            }
            Err(e) => {
                error!(
                    r#"❌ Can't reach the homeserver at "{client_versions}".
This may be due to a misconfiguration in the `matrix` section of the config.

  matrix:
    homeserver: "{matrix_domain}"
    # The homeserver should be reachable at this URL
    endpoint: "{hs_api}"

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
                );
                false
            }
        };

        if can_reach_cs {
            // Try the whoami API. If it replies with `M_UNKNOWN` this is because Synapse
            // couldn't reach MAS
            let whoami = hs_api.join("/_matrix/client/v3/account/whoami")?;
            let request = hyper::Request::builder()
                .header(
                    "Authorization",
                    "Bearer averyinvalidtokenireallyhopethisisnotvalid",
                )
                .uri(whoami.as_str())
                .body(axum::body::Body::empty())?;
            let result = client.ready().await?.call(request).await;
            match result {
                Ok(response) => {
                    let (parts, body) = response.into_parts();
                    let status = parts.status;

                    match status.as_u16() {
                        401 => info!(
                            r#"✅ Homeserver at "{whoami}" is reachable, and it correctly rejected an invalid token."#
                        ),

                        0..=399 => error!(
                            r#"❌ The homeserver at "{whoami}" replied with {status}.
This is *highly* unexpected, as this means that a fake token might have been accepted.
"#
                        ),

                        503 => error!(
                            r#"❌ The homeserver at "{whoami}" replied with {status}.
This means probably means that the homeserver was unable to reach MAS to validate the token.
Make sure MAS is running and reachable from Synapse.
Check your homeserver logs.

This is what the homeserver told us about the error:

    {body}

See {DOCS_BASE}/setup/homeserver.html
"#
                        ),

                        _ => warn!(
                            r#"⚠️ The homeserver at "{whoami}" replied with {status}.
Check that the homeserver is running."#
                        ),
                    }
                }
                Err(e) => error!(
                    r#"❌ Can't reach the homeserver at "{whoami}".

Error details: {e}
"#
                ),
            }

            // Try to reach the admin API on an unauthorized endpoint
            let server_version = hs_api.join("/_synapse/admin/v1/server_version")?;
            let request = hyper::Request::builder()
                .uri(server_version.as_str())
                .body(axum::body::Body::empty())?;
            let result = client.ready().await?.call(request).await;
            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        info!(r#"✅ The Synapse admin API is reachable at "{server_version}"."#);
                    } else {
                        error!(
                            r#"❌ A Synapse admin API endpoint at "{server_version}" replied with {status}.
Make sure MAS can reach the admin API, and that the homeserver is running.
"#
                        );
                    }
                }
                Err(e) => error!(
                    r#"❌ Can't reach the Synapse admin API at "{server_version}".
Make sure MAS can reach the admin API, and that the homeserver is running.

Error details: {e}
"#
                ),
            }

            // Try to reach an authenticated admin API endpoint
            let background_updates = hs_api.join("/_synapse/admin/v1/background_updates/status")?;
            let request = hyper::Request::builder()
                .uri(background_updates.as_str())
                .header("Authorization", format!("Bearer {admin_token}"))
                .body(axum::body::Body::empty())?;
            let result = client.ready().await?.call(request).await;
            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        info!(
                            r#"✅ The Synapse admin API is reachable with authentication at "{background_updates}"."#
                        );
                    } else {
                        error!(
                            r#"❌ A Synapse admin API endpoint at "{background_updates}" replied with {status}.
Make sure the homeserver is running, and that the MAS config has the correct `matrix.secret`.
It should match the `admin_token` set in the Synapse config.

  experimental_features:
    msc3861:
      enabled: true
      issuer: {issuer}
      # This must exactly match the secret in the MAS config:
      admin_token: {admin_token:?}

And in the MAS config:

  matrix:
    homeserver: "{matrix_domain}"
    endpoint: "{hs_api}"
    secret: {admin_token:?}
"#
                        );
                    }
                }
                Err(e) => error!(
                    r#"❌ Can't reach the Synapse admin API at "{background_updates}".
Make sure the homeserver is running, and that the MAS config has the correct `matrix.secret`.

Error details: {e}
"#
                ),
            }
        }

        let external_cs_api_endpoint = discovered_cs_api.as_ref().unwrap_or(&hs_api);
        // Try to reach the legacy login API
        let compat_login = external_cs_api_endpoint.join("/_matrix/client/v3/login")?;
        let compat_login = compat_login.as_str();
        let request = hyper::Request::builder()
            .uri(compat_login)
            .body(axum::body::Body::empty())?;
        let result = client.ready().await?.call(request).await;
        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    // Now we need to inspect the body to figure out whether it's Synapse or MAS
                    // which handled the request
                    let body = response.into_body();
                    let flows = body
                        .get("flows")
                        .and_then(|flows| flows.as_array())
                        .map(std::vec::Vec::as_slice)
                        .unwrap_or_default();

                    let has_compatibility_sso = flows.iter().any(|flow| {
                        flow.get("type").and_then(|t| t.as_str()) == Some("m.login.sso")
                            && flow
                                .get("org.matrix.msc3824.delegated_oidc_compatibility")
                                .and_then(serde_json::Value::as_bool)
                                == Some(true)
                    });

                    if has_compatibility_sso {
                        info!(
                            r#"✅ The legacy login API at "{compat_login}" is reachable and is handled by MAS."#
                        );
                    } else {
                        warn!(
                            r#"⚠️ The legacy login API at "{compat_login}" is reachable, but it doesn't look to be handled by MAS.
This means legacy clients won't be able to login.
Make sure MAS is running.
Check your reverse proxy settings to make sure that this API is handled by MAS, not by Synapse.

See {DOCS_BASE}/setup/reverse-proxy.html
"#
                        );
                    }
                } else {
                    error!(
                        r#"The legacy login API at "{compat_login}" replied with {status}.
This means legacy clients won't be able to login.
Make sure MAS is running.
Check your reverse proxy settings to make sure that this API is handled by MAS, not by Synapse.

See {DOCS_BASE}/setup/reverse-proxy.html
"#
                    );
                }
            }
            Err(e) => warn!(
                r#"⚠️ Can't reach the legacy login API at "{compat_login}".
This means legacy clients won't be able to login.
Make sure MAS is running.
Check your reverse proxy settings to make sure that this API is handled by MAS, not by Synapse.

See {DOCS_BASE}/setup/reverse-proxy.html

Error details: {e}"#
            ),
        }

        Ok(ExitCode::SUCCESS)
    }
}
