use std::collections::HashMap;

use async_std::sync::RwLock;

mod client;
mod user;

pub use self::client::{Client, ClientLookupError, InvalidRedirectUriError};
pub use self::user::User;

#[derive(Debug, Default)]
pub struct Storage {
    clients: RwLock<HashMap<String, Client>>,
    users: RwLock<HashMap<String, User>>,
}
