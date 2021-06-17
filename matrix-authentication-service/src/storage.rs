use std::collections::HashSet;

use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct Storage;

pub struct Client {
    redirect_uris: Option<HashSet<Url>>,
}

#[derive(Debug, Error)]
#[error("Invalid redirect URI")]
pub struct InvalidRedirectUriError;

impl Client {
    pub fn resolve_redirect_uri(
        &self,
        suggested_uri: Option<Url>,
    ) -> Result<Url, InvalidRedirectUriError> {
        match (suggested_uri, &self.redirect_uris) {
            (None, None) => Err(InvalidRedirectUriError),
            (None, Some(redirect_uris)) => redirect_uris
                .iter()
                .next()
                .cloned()
                .ok_or(InvalidRedirectUriError),
            (Some(suggested_uri), None) => Ok(suggested_uri),
            (Some(suggested_uri), Some(redirect_uris)) => {
                if redirect_uris.contains(&suggested_uri) {
                    Ok(suggested_uri)
                } else {
                    Err(InvalidRedirectUriError)
                }
            }
        }
    }
}

#[derive(Debug, Error)]
#[error("Could not find client")]
pub struct ClientLookupError;

impl Storage {
    pub async fn lookup_client(&self, _client_id: &str) -> Result<Client, ClientLookupError> {
        Ok(Client {
            redirect_uris: None,
        })
    }
}
