use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub redirect_uris: Option<Vec<Url>>,
}

fn default_oauth2_issuer() -> Url {
    "http://[::]:8080".parse().unwrap()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_oauth2_issuer")]
    pub issuer: Url,

    #[serde(default)]
    pub clients: Vec<ClientConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            issuer: default_oauth2_issuer(),
            clients: Default::default(),
        }
    }
}
