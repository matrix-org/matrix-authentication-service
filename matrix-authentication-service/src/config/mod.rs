use figment::{
    error::Error as FigmentError,
    providers::{Env, Format, Yaml},
    Figment,
};
use serde::Deserialize;

mod http;
mod oauth2;

pub use self::http::Config as HttpConfig;
pub use self::oauth2::{ClientConfig as OAuth2ClientConfig, Config as OAuth2Config};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RootConfig {
    pub oauth2: OAuth2Config,
    pub http: HttpConfig,
}

impl RootConfig {
    pub fn load() -> Result<RootConfig, FigmentError> {
        Figment::new()
            .merge(Env::prefixed("MAS_").split("_"))
            .merge(Yaml::file("config.yaml"))
            .extract()
    }
}
