// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
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

use std::sync::{Arc, Mutex};

use mas_axum_utils::{cookies::CookieJar, http_client_factory::HttpClientFactory};
use mas_data_model::{SiteConfig, UserAgent};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, RepositoryError};

use crate::{graphql::Requester, passwords::PasswordManager, BoundActivityTracker};

#[async_trait::async_trait]
pub trait State {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError>;
    async fn policy(&self) -> Result<Policy, mas_policy::InstantiateError>;
    fn password_manager(&self) -> PasswordManager;
    fn homeserver_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error>;
    fn clock(&self) -> BoxClock;
    fn rng(&self) -> BoxRng;
    fn site_config(&self) -> &SiteConfig;
    fn http_client_factory(&self) -> &HttpClientFactory;
    fn url_builder(&self) -> &UrlBuilder;
}

pub type BoxState = Box<dyn State + Send + Sync + 'static>;

pub trait ContextExt {
    fn state(&self) -> &BoxState;

    fn requester(&self) -> &Requester;

    /// Get the parsed user agent of the client making the request.
    /// Not guaranteed to be present.
    fn user_agent(&self) -> Option<&UserAgent>;

    /// Get the preferred language/locale of the client making the request.
    fn preferred_locale(&self) -> &DataLocale;

    /// Get the activity tracker bound to the requester.
    fn activity_tracker(&self) -> &BoundActivityTracker;

    /// Get a wrapper for the cookie jar, which can be used to view and set
    /// cookies.
    fn cookie_jar(&self) -> &GraphQLCookieJar;
}

impl ContextExt for async_graphql::Context<'_> {
    fn state(&self) -> &BoxState {
        self.data_unchecked()
    }

    fn requester(&self) -> &Requester {
        self.data_unchecked()
    }

    fn user_agent(&self) -> Option<&UserAgent> {
        self.data_unchecked::<Option<UserAgent>>().as_ref()
    }

    fn preferred_locale(&self) -> &DataLocale {
        self.data_unchecked()
    }

    fn activity_tracker(&self) -> &BoundActivityTracker {
        self.data_unchecked()
    }

    fn cookie_jar(&self) -> &GraphQLCookieJar {
        // This Arc should never be cloned, as the request must not have any strong
        // references to it after the request is finished. This way, the request
        // handling code can unwrap the Arc afterwards and send the cookies to the HTTP
        // client.
        self.data_unchecked::<Arc<GraphQLCookieJar>>()
    }
}

pub struct GraphQLCookieJar {
    /// The underlying cookie jar.
    /// The cookie jar is always present,
    /// the option is just so we can borrow it temporarily but it should always
    /// be returned immediately.
    jar: Mutex<Option<CookieJar>>,
}

impl GraphQLCookieJar {
    /// Create a new wrapper for the cookie jar
    pub fn new(jar: CookieJar) -> Self {
        Self {
            jar: Mutex::new(Some(jar)),
        }
    }

    /// Unwrap the cookie jar
    pub fn into_inner(self) -> CookieJar {
        // unwrap: the cookie jar is always present and we don't care about handling
        // poisoned mutexes
        self.jar.into_inner().unwrap().unwrap()
    }

    /// Operate on the cookie jar, by taking it and replacing it with a new
    /// (modified) one.
    pub fn with(&self, f: impl FnOnce(CookieJar) -> CookieJar) {
        // unwrap: poisoned mutexes are not worth handling
        let mut jar_guard = self.jar.lock().unwrap();
        // unwrap: the cookie jar is always present
        let jar = jar_guard.take().unwrap();
        *jar_guard = Some(f(jar));
    }

    /// Access (read-only) the cookie jar
    #[allow(dead_code)]
    pub fn inspect<T>(&self, f: impl FnOnce(&CookieJar) -> T) -> T {
        // unwrap: poisoned mutexes are not worth handling
        let jar_guard = self.jar.lock().unwrap();
        // unwrap: the cookie jar is always present
        let jar = jar_guard.as_ref().unwrap();
        f(jar)
    }
}
