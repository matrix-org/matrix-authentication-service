use std::sync::Arc;

use url::Url;

use crate::{config::Config, storage::Storage};

#[derive(Debug, Clone)]
pub struct State {
    config: Arc<Config>,
    storage: Storage,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            storage: Default::default(),
        }
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    fn base(&self) -> Url {
        self.config.oauth2.issuer.clone()
    }

    pub fn issuer(&self) -> Url {
        self.base()
    }

    pub fn authorization_endpoint(&self) -> Option<Url> {
        self.base().join("oauth2/authorize").ok()
    }

    pub fn token_endpoint(&self) -> Option<Url> {
        self.base().join("oauth2/token").ok()
    }

    pub fn jwks_uri(&self) -> Option<Url> {
        self.base().join(".well-known/jwks.json").ok()
    }
}
