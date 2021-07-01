use figment::{
    error::Error as FigmentError,
    providers::{Env, Format, Yaml},
    Figment,
};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct OAuth2ClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub redirect_uris: Option<Vec<Url>>,
}

fn default_oauth2_issuer() -> Url {
    "http://[::]:8080".parse().unwrap()
}

#[derive(Debug, Deserialize)]
pub struct OAuth2Config {
    #[serde(default = "default_oauth2_issuer")]
    pub issuer: Url,

    #[serde(default)]
    pub clients: Vec<OAuth2ClientConfig>,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            issuer: default_oauth2_issuer(),
            clients: Default::default(),
        }
    }
}

fn default_listener_address() -> String {
    "[::]:8080".into()
}

#[derive(Debug, Deserialize)]
pub struct ListenerConfig {
    #[serde(default = "default_listener_address")]
    pub address: String,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig {
            address: default_listener_address(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RootConfig {
    pub oauth2: OAuth2Config,
    pub listener: ListenerConfig,
}

impl RootConfig {
    pub fn load() -> Result<RootConfig, FigmentError> {
        Figment::new()
            .merge(Env::prefixed("MAS_").split("_"))
            .merge(Yaml::file("config.yaml"))
            .extract()
    }
}
