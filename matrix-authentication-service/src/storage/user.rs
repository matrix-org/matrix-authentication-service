// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

impl<T> super::Storage<T> {
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
