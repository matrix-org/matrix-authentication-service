use serde::Deserialize;

fn default_http_address() -> String {
    "[::]:8080".into()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_http_address")]
    pub address: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            address: default_http_address(),
        }
    }
}
