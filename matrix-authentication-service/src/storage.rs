use std::collections::{HashMap, HashSet};

use async_std::sync::{RwLock, RwLockUpgradableReadGuard};
use serde::Serialize;
use thiserror::Error;
use url::Url;

#[derive(Debug, Default)]
pub struct Storage {
    clients: RwLock<HashMap<String, Client>>,
    users: RwLock<HashMap<String, User>>,
}

#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
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

#[derive(Debug, Error)]
#[error("Invalid credentials")]
pub struct UserLoginError;

#[derive(Debug, Error)]
#[error("Could not find user")]
pub struct UserLookupError;

#[derive(Serialize, Debug, Clone)]
pub struct User {
    name: String,
}

impl User {
    pub fn key(&self) -> &str {
        &self.name
    }
}

impl Storage {
    pub async fn lookup_client(&self, client_id: &str) -> Result<Client, ClientLookupError> {
        // First lookup for an existing client
        let clients = self.clients.upgradable_read().await;
        if let Some(client) = clients.get(client_id) {
            Ok(client.clone())
        } else {
            // If it does not exist, insert a new client
            let mut clients = RwLockUpgradableReadGuard::upgrade(clients).await;
            let new_client = Client {
                client_id: client_id.to_string(),
                redirect_uris: None,
            };
            clients.insert(client_id.to_string(), new_client.clone());
            Ok(new_client)
        }
    }

    pub async fn login(&self, name: &str, password: &str) -> Result<User, UserLoginError> {
        // Hardcoded bad password to test login failures
        if password == "bad" {
            Err(UserLoginError)
        } else {
            // First lookup for an existing user
            let users = self.users.upgradable_read().await;
            if let Some(user) = users.get(name) {
                Ok(user.clone())
            } else {
                // If it does not exist, insert a new user
                let mut users = RwLockUpgradableReadGuard::upgrade(users).await;
                let new_user = User {
                    name: name.to_string(),
                };
                users.insert(name.to_string(), new_user.clone());
                Ok(new_user)
            }
        }
    }

    pub async fn lookup_user(&self, name: &str) -> Result<User, UserLookupError> {
        let users = self.users.read().await;
        users.get(name).cloned().ok_or(UserLookupError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
