use std::collections::HashSet;

use thiserror::Error;
use url::Url;

use crate::config::OAuth2ClientConfig;

#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
    redirect_uris: Option<HashSet<Url>>,
}

#[derive(Debug, Error)]
#[error("Could not find client")]
pub struct ClientLookupError;

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

impl super::Storage {
    pub async fn load_static_clients(&self, clients: &[OAuth2ClientConfig]) {
        let mut storage = self.clients.write().await;
        for config in clients {
            let redirect_uris = config
                .redirect_uris
                .as_ref()
                .map(|uris| uris.iter().cloned().collect());
            let client_id = config.client_id.clone();

            let client = Client {
                client_id: client_id.clone(),
                redirect_uris,
            };

            // TODO: we could warn about duplicate clients here
            storage.insert(client_id, client);
        }
    }

    pub async fn lookup_client(&self, client_id: &str) -> Result<Client, ClientLookupError> {
        self.clients
            .read()
            .await
            .get(client_id)
            .cloned()
            .ok_or(ClientLookupError)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Storage;

    #[async_std::test]
    async fn test_login() {
        let storage = Storage::default();

        // "bad" is a bad password and should not insert
        assert_eq!(storage.users.read().await.len(), 0);
        assert!(storage.login("hello", "bad").await.is_err());
        assert_eq!(storage.users.read().await.len(), 0);

        // Logging in with the same user should only insert once
        assert!(storage.login("hello", "good").await.is_ok());
        assert_eq!(storage.users.read().await.len(), 1);
        assert!(storage.login("hello", "good").await.is_ok());
        assert_eq!(storage.users.read().await.len(), 1);

        // Logging in with another user should also do an insert
        assert!(storage.login("world", "good").await.is_ok());
        assert_eq!(storage.users.read().await.len(), 2);
    }
}
