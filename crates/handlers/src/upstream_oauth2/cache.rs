// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::{collections::HashMap, sync::Arc};

use mas_http::HttpService;
use mas_oidc_client::error::DiscoveryError;
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, RepositoryAccess};
use oauth2_types::oidc::VerifiedProviderMetadata;
use tokio::sync::RwLock;

/// A simple OIDC metadata cache
///
/// It never evicts entries, does not cache failures and has no locking.
/// It can also be refreshed in the background, and warmed up on startup.
/// It is good enough for our use case.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct MetadataCache {
    cache: Arc<RwLock<HashMap<String, VerifiedProviderMetadata>>>,
}

impl MetadataCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm up the cache by fetching all the known providers from the database
    /// and inserting them into the cache.
    ///
    /// This spawns a background task that will refresh the cache at the given
    /// interval.
    #[tracing::instrument(name = "metadata_cache.warm_up_and_run", skip_all, err)]
    pub async fn warm_up_and_run<R: RepositoryAccess>(
        &self,
        http_service: HttpService,
        interval: std::time::Duration,
        repository: &mut R,
    ) -> Result<tokio::task::JoinHandle<()>, R::Error> {
        let providers = repository.upstream_oauth_provider().all().await?;

        for provider in providers {
            if let Err(e) = self.fetch(&http_service, &provider.issuer).await {
                tracing::error!(issuer = %provider.issuer, error = &e as &dyn std::error::Error, "Failed to fetch provider metadata");
            }
        }

        // Spawn a background task to refresh the cache regularly
        let cache = self.clone();
        Ok(tokio::spawn(async move {
            loop {
                // Re-fetch the known metadata at the given interval
                tokio::time::sleep(interval).await;
                cache.refresh_all(&http_service).await;
            }
        }))
    }

    #[tracing::instrument(name = "metadata_cache.fetch", fields(%issuer), skip_all, err)]
    async fn fetch(
        &self,
        http_service: &HttpService,
        issuer: &str,
    ) -> Result<VerifiedProviderMetadata, DiscoveryError> {
        let metadata = mas_oidc_client::requests::discovery::discover(http_service, issuer).await?;

        self.cache
            .write()
            .await
            .insert(issuer.to_owned(), metadata.clone());

        Ok(metadata)
    }

    /// Get the metadata for the given issuer.
    #[tracing::instrument(name = "metadata_cache.get", fields(%issuer), skip_all, err)]
    pub async fn get(
        &self,
        http_service: &HttpService,
        issuer: &str,
    ) -> Result<VerifiedProviderMetadata, DiscoveryError> {
        let cache = self.cache.read().await;
        if let Some(metadata) = cache.get(issuer) {
            return Ok(metadata.clone());
        }

        let metadata = self.fetch(http_service, issuer).await?;
        Ok(metadata)
    }

    #[tracing::instrument(name = "metadata_cache.refresh_all", skip_all)]
    async fn refresh_all(&self, http_service: &HttpService) {
        // Grab all the keys first to avoid locking the cache for too long
        let keys: Vec<String> = {
            let cache = self.cache.read().await;
            cache.keys().cloned().collect()
        };

        for issuer in keys {
            if let Err(e) = self.fetch(http_service, &issuer).await {
                tracing::error!(issuer = %issuer, error = &e as &dyn std::error::Error, "Failed to refresh provider metadata");
            }
        }
    }
}
