use async_std::sync::RwLockUpgradableReadGuard;
use serde::Serialize;
use thiserror::Error;

#[derive(Serialize, Debug, Clone)]
pub struct User {
    name: String,
}

impl User {
    pub fn key(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Error)]
#[error("Invalid credentials")]
pub struct UserLoginError;

#[derive(Debug, Error)]
#[error("Could not find user")]
pub struct UserLookupError;

impl super::Storage {
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
