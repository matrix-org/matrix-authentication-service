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

use std::{
    borrow::Cow,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    ops::Deref,
    os::unix::net::UnixListener,
    path::PathBuf,
};

use anyhow::{bail, Context};
use async_trait::async_trait;
use listenfd::ListenFd;
use mas_keystore::PrivateKey;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(rename_all = "lowercase")]
pub enum UnixOrTcp {
    Unix,
    Tcp,
}

impl UnixOrTcp {
    pub const fn unix() -> Self {
        Self::Unix
    }

    pub const fn tcp() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(untagged)]
pub enum BindConfig {
    Listen {
        host: Option<String>,
        port: u16,
    },

    Address {
        #[schemars(
            example = "http_address_example_1",
            example = "http_address_example_2",
            example = "http_address_example_3",
            example = "http_address_example_4"
        )]
        address: String,
    },

    Unix {
        socket: PathBuf,
    },

    FileDescriptor {
        fd: usize,

        #[serde(default = "UnixOrTcp::tcp")]
        kind: UnixOrTcp,
    },
}

impl BindConfig {
    // TODO: move this somewhere else
    pub fn listener<T>(&self, fd_manager: &mut ListenFd) -> Result<T, anyhow::Error>
    where
        T: TryFrom<TcpListener> + TryFrom<UnixListener>,
        <T as TryFrom<TcpListener>>::Error: std::error::Error + Sync + Send + 'static,
        <T as TryFrom<UnixListener>>::Error: std::error::Error + Sync + Send + 'static,
    {
        match self {
            BindConfig::Listen { host, port } => {
                let addrs = match host.as_deref() {
                    Some(host) => (host, *port)
                        .to_socket_addrs()
                        .context("could not parse listener host")?
                        .collect(),

                    None => vec![
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), *port),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port),
                    ],
                };

                let listener = TcpListener::bind(&addrs[..]).context("could not bind address")?;
                listener.set_nonblocking(true)?;
                Ok(listener.try_into()?)
            }

            BindConfig::Address { address } => {
                let addr: SocketAddr = address
                    .parse()
                    .context("could not parse listener address")?;
                let listener = TcpListener::bind(addr).context("could not bind address")?;
                listener.set_nonblocking(true)?;
                Ok(listener.try_into()?)
            }

            BindConfig::Unix { socket } => {
                let listener = UnixListener::bind(socket).context("could not bind socket")?;
                listener.set_nonblocking(true)?;
                Ok(listener.try_into()?)
            }

            BindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Tcp,
            } => {
                let listener = fd_manager
                    .take_tcp_listener(*fd)?
                    .context("no listener found on file descriptor")?;
                listener.set_nonblocking(true)?;
                Ok(listener.try_into()?)
            }

            BindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Unix,
            } => {
                let listener = fd_manager
                    .take_unix_listener(*fd)?
                    .context("no unix socket found on file descriptor")?;
                listener.set_nonblocking(true)?;
                Ok(listener.try_into()?)
            }
        }
    }
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

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TlsConfig {
    #[serde(flatten)]
    pub certificate: CertificateOrFile,

    #[serde(flatten)]
    pub key: KeyOrFile,

    #[serde(flatten)]
    pub password: Option<PasswordOrFile>,
}

impl TlsConfig {
    pub async fn load(&self) -> Result<(Vec<u8>, Vec<Vec<u8>>), anyhow::Error> {
        let password = match &self.password {
            Some(PasswordOrFile::Password(password)) => Some(Cow::Borrowed(password.as_str())),
            Some(PasswordOrFile::PasswordFile(path)) => {
                Some(Cow::Owned(tokio::fs::read_to_string(path).await?))
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
                let key = tokio::fs::read(path).await?;
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
            CertificateOrFile::CertificateFile(path) => {
                Cow::Owned(tokio::fs::read_to_string(path).await?)
            }
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
    Static,
}

/// Configuration of a listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListenerConfig {
    /// List of resources to mount
    pub resources: Vec<Resource>,

    /// List of sockets to bind
    pub binds: Vec<BindConfig>,

    /// If set, makes the listener use TLS with the provided certificate and key
    pub tls: Option<TlsConfig>,
}

/// Configuration related to the web server
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpConfig {
    /// List of listeners to run
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// Path from which to serve static files. If not specified, it will serve
    /// the static files embedded in the server binary
    #[serde(default)]
    pub web_root: Option<PathBuf>,

    /// Public URL base from where the authentication service is reachable
    pub public_base: Url,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            web_root: None,
            listeners: vec![
                ListenerConfig {
                    resources: vec![
                        Resource::Discovery,
                        Resource::Human,
                        Resource::OAuth,
                        Resource::Compat,
                        Resource::Static,
                    ],
                    tls: None,
                    binds: vec![BindConfig::Address {
                        address: "[::]:8080".into(),
                    }],
                },
                ListenerConfig {
                    resources: vec![Resource::Health],
                    tls: None,
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
