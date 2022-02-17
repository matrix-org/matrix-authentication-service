// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use futures_util::future::BoxFuture;
use thiserror::Error;
use tokio::sync::RwLock;
use tower::{
    util::{BoxCloneService, ServiceExt},
    BoxError, Service,
};

use super::StaticJwksStore;
use crate::{JsonWebKeySet, JwtHeader, VerifyingKeystore};

#[derive(Debug, Error)]
pub enum Error {
    #[error("cache in inconsistent state")]
    InconsistentCache,

    #[error(transparent)]
    Cached(Arc<BoxError>),

    #[error("todo")]
    Todo,

    #[error(transparent)]
    Verification(#[from] super::static_store::Error),
}

enum State<E> {
    Pending,
    Errored {
        at: DateTime<Utc>,
        error: E,
    },
    Fulfilled {
        at: DateTime<Utc>,
        store: StaticJwksStore,
    },
}

impl<E> Default for State<E> {
    fn default() -> Self {
        Self::Pending
    }
}

impl<E> State<E> {
    fn fullfill(&mut self, key_set: JsonWebKeySet) {
        *self = Self::Fulfilled {
            at: Utc::now(),
            store: StaticJwksStore::new(key_set),
        }
    }

    fn error(&mut self, error: E) {
        *self = Self::Errored {
            at: Utc::now(),
            error,
        }
    }

    fn should_refresh(&self) -> bool {
        let now = Utc::now();
        match self {
            Self::Pending => true,
            Self::Errored { at, .. } if *at - now > Duration::minutes(5) => true,
            Self::Fulfilled { at, .. } if *at - now > Duration::hours(1) => true,
            _ => false,
        }
    }

    fn should_force_refresh(&self) -> bool {
        let now = Utc::now();
        match self {
            Self::Pending => true,
            Self::Errored { at, .. } | Self::Fulfilled { at, .. }
                if *at - now > Duration::minutes(5) =>
            {
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct DynamicJwksStore {
    exporter: BoxCloneService<(), JsonWebKeySet, BoxError>,
    cache: Arc<RwLock<State<Arc<BoxError>>>>,
}

impl DynamicJwksStore {
    pub fn new<T>(exporter: T) -> Self
    where
        T: Service<(), Response = JsonWebKeySet, Error = BoxError> + Send + Clone + 'static,
        T::Future: Send,
    {
        Self {
            exporter: exporter.boxed_clone(),
            cache: Arc::default(),
        }
    }
}

impl VerifyingKeystore for DynamicJwksStore {
    type Error = Error;
    type Future = BoxFuture<'static, Result<(), Self::Error>>;

    fn verify(&self, header: &JwtHeader, payload: &[u8], signature: &[u8]) -> Self::Future {
        let cache = self.cache.clone();
        let exporter = self.exporter.clone();
        let header = header.clone();
        let payload = payload.to_owned();
        let signature = signature.to_owned();

        let fut = async move {
            if cache.read().await.should_refresh() {
                let mut cache = cache.write().await;

                if cache.should_force_refresh() {
                    let jwks = async move { exporter.ready_oneshot().await?.call(()).await }.await;

                    match jwks {
                        Ok(jwks) => cache.fullfill(jwks),
                        Err(err) => cache.error(Arc::new(err)),
                    }
                }
            }

            let cache = cache.read().await;
            // TODO: we could bubble up the underlying error here
            let store = match &*cache {
                State::Pending => return Err(Error::InconsistentCache),
                State::Errored { error, .. } => return Err(Error::Cached(error.clone())),
                State::Fulfilled { store, .. } => store,
            };

            store.verify(&header, &payload, &signature).await?;

            Ok(())
        };

        Box::pin(fut)
    }
}
