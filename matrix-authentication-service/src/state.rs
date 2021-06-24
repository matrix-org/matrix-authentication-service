use std::sync::Arc;

use tera::Tera;
use url::Url;

use crate::{config::Config, storage::Storage};

#[derive(Debug, Clone)]
pub struct State {
    config: Arc<Config>,
    templates: Arc<Tera>,
    storage: Storage,
}

impl State {
    pub fn new(config: Config, templates: Tera) -> Self {
        Self {
            config: Arc::new(config),
            templates: Arc::new(templates),
            storage: Default::default(),
        }
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn templates(&self) -> &Tera {
        &self.templates
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
