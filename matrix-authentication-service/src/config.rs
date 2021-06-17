use figment::{error::Error as FigmentError, providers::Env, Figment};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct OAuth2 {
    pub issuer: Url,
}

impl Default for OAuth2 {
    fn default() -> Self {
        Self {
            issuer: "http://[::]:8080".parse().unwrap(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub address: String,
}

impl Default for Listener {
    fn default() -> Self {
        Listener {
            address: "[::]:8080".into(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub oauth2: OAuth2,
    pub listener: Listener,
}

impl Config {
    pub fn load() -> Result<Config, FigmentError> {
        Figment::new()
            .merge(Env::prefixed("MAS_").split("_"))
            .extract()
    }
}
