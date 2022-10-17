// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use std::{borrow::Cow, io::Cursor, ops::Deref, path::PathBuf};

use anyhow::bail;
use async_trait::async_trait;
use mas_keystore::PrivateKey;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use super::{secrets::PasswordOrFile, ConfigurationSection};

fn default_public_base() -> Url {
    "http://[::]:8080".parse().unwrap()
}

fn http_address_example_1() -> &'static str {
    "[::1]:8080"
}
fn http_address_example_2() -> &'static str {
    "[::]:8080"
}
fn http_address_example_3() -> &'static str {
    "127.0.0.1:8080"
}
fn http_address_example_4() -> &'static str {
    "0.0.0.0:8080"
}

/// Kind of socket
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum UnixOrTcp {
    /// UNIX domain socket
    Unix,

    /// TCP socket
    Tcp,
}

impl UnixOrTcp {
    /// UNIX domain socket
    #[must_use]
    pub const fn unix() -> Self {
        Self::Unix
    }

    /// TCP socket
    #[must_use]
    pub const fn tcp() -> Self {
        Self::Tcp
    }
}

/// Configuration of a single listener
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(untagged)]
pub enum BindConfig {
    /// Listen on the specified host and port
    Listen {
        /// Host on which to listen.
        ///
        /// Defaults to listening on all addresses
        #[serde(default)]
        host: Option<String>,

        /// Port on which to listen.
        port: u16,
    },

    /// Listen on the specified address
    Address {
        /// Host and port on which to listen
        #[schemars(
            example = "http_address_example_1",
            example = "http_address_example_2",
            example = "http_address_example_3",
            example = "http_address_example_4"
        )]
        address: String,
    },

    /// Listen on a UNIX domain socket
    Unix {
        /// Path to the socket
        socket: PathBuf,
    },

    /// Accept connections on file descriptors passed by the parent process.
    ///
    /// This is useful for grabbing sockets passed by systemd.
    ///
    /// See <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>
    FileDescriptor {
        /// Index of the file descriptor. Note that this is offseted by 3
        /// because of the standard input/output sockets, so setting
        /// here a value of `0` will grab the file descriptor `3`
        #[serde(default)]
        fd: usize,

        /// Whether the socket is a TCP socket or a UNIX domain socket. Defaults
        /// to TCP.
        #[serde(default = "UnixOrTcp::tcp")]
        kind: UnixOrTcp,
    },
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrFile {
    Key(String),
    KeyFile(PathBuf),
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CertificateOrFile {
    Certificate(String),
    CertificateFile(PathBuf),
}

/// Configuration related to TLS on a listener
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TlsConfig {
    /// PEM-encoded X509 certificate chain
    #[serde(flatten)]
    pub certificate: CertificateOrFile,

    /// Private key
    #[serde(flatten)]
    pub key: KeyOrFile,

    /// Password used to decode the private key
    #[serde(flatten)]
    pub password: Option<PasswordOrFile>,
}

impl TlsConfig {
    /// Load the TLS certificate chain and key file from disk
    ///
    /// # Errors
    ///
    /// Returns an error if an error was encountered either while:
    ///   - reading the certificate, key or password files
    ///   - decoding the key as PEM or DER
    ///   - decrypting the key if encrypted
    ///   - a password was provided but the key was not encrypted
    ///   - decoding the certificate chain as PEM
    ///   - the certificate chain is empty
    pub fn load(&self) -> Result<(Vec<u8>, Vec<Vec<u8>>), anyhow::Error> {
        let password = match &self.password {
            Some(PasswordOrFile::Password(password)) => Some(Cow::Borrowed(password.as_str())),
            Some(PasswordOrFile::PasswordFile(path)) => {
                Some(Cow::Owned(std::fs::read_to_string(path)?))
            }
            None => None,
        };

        // Read the key either embedded in the config file or on disk
        let key = match &self.key {
            KeyOrFile::Key(key) => {
                // If the key was embedded in the config file, assume it is formatted as PEM
                if let Some(password) = password {
                    PrivateKey::load_encrypted_pem(key, password.as_bytes())?
                } else {
                    PrivateKey::load_pem(key)?
                }
            }
            KeyOrFile::KeyFile(path) => {
                // When reading from disk, it might be either PEM or DER. `PrivateKey::load*`
                // will try both.
                let key = std::fs::read(path)?;
                if let Some(password) = password {
                    PrivateKey::load_encrypted(&key, password.as_bytes())?
                } else {
                    PrivateKey::load(&key)?
                }
            }
        };

        // Re-serialize the key to PKCS#8 DER, so rustls can consume it
        let key = key.to_pkcs8_der()?;
        // This extracts the Vec out of the Zeroizing by copying it
        // XXX: maybe we should keep that zeroizing?
        let key = key.deref().clone();

        let certificate_chain_pem = match &self.certificate {
            CertificateOrFile::Certificate(pem) => Cow::Borrowed(pem.as_str()),
            CertificateOrFile::CertificateFile(path) => Cow::Owned(std::fs::read_to_string(path)?),
        };

        let mut certificate_chain_reader = Cursor::new(certificate_chain_pem.as_bytes());
        let certificate_chain = rustls_pemfile::certs(&mut certificate_chain_reader)?;

        if certificate_chain.is_empty() {
            bail!("TLS certificate chain is empty (or invalid)")
        }

        Ok((key, certificate_chain))
    }
}

/// HTTP resources to mount
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "name", rename_all = "lowercase")]
pub enum Resource {
    /// Healthcheck endpoint (/health)
    Health,

    /// Prometheus metrics endpoint (/metrics)
    Prometheus,

    /// OIDC discovery endpoints
    Discovery,

    /// Pages destined to be viewed by humans
    Human,

    /// OAuth-related APIs
    OAuth,

    /// Matrix compatibility API
    Compat,

    /// Static files
    Static {
        /// Path from which to serve static files. If not specified, it will
        /// serve the static files embedded in the server binary
        #[serde(default)]
        web_root: Option<PathBuf>,
    },

    /// Mount a "/connection-info" handler which helps debugging informations on
    /// the upstream connection
    #[serde(rename = "connection-info")]
    ConnectionInfo,
}

/// Configuration of a listener
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListenerConfig {
    /// A unique name for this listener which will be shown in traces and in
    /// metrics labels
    #[serde(default)]
    pub name: Option<String>,

    /// List of resources to mount
    pub resources: Vec<Resource>,

    /// List of sockets to bind
    pub binds: Vec<BindConfig>,

    /// Accept HAProxy's Proxy Protocol V1
    #[serde(default)]
    pub proxy_protocol: bool,

    /// If set, makes the listener use TLS with the provided certificate and key
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Configuration related to the web server
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpConfig {
    /// List of listeners to run
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// Public URL base from where the authentication service is reachable
    pub public_base: Url,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listeners: vec![
                ListenerConfig {
                    name: Some("web".to_owned()),
                    resources: vec![
                        Resource::Discovery,
                        Resource::Human,
                        Resource::OAuth,
                        Resource::Compat,
                        Resource::Static { web_root: None },
                    ],
                    tls: None,
                    proxy_protocol: false,
                    binds: vec![BindConfig::Address {
                        address: "[::]:8080".into(),
                    }],
                },
                ListenerConfig {
                    name: Some("internal".to_owned()),
                    resources: vec![Resource::Health],
                    tls: None,
                    proxy_protocol: false,
                    binds: vec![BindConfig::Address {
                        address: "localhost:8081".into(),
                    }],
                },
            ],
            public_base: default_public_base(),
        }
    }
}

#[async_trait]
impl ConfigurationSection<'_> for HttpConfig {
    fn path() -> &'static str {
        "http"
    }

    async fn generate() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    fn test() -> Self {
        Self::default()
    }
}
