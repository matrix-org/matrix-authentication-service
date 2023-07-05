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

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::missing_crate_level_docs,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]

//! A crate to help serve single-page apps built by Vite.

mod vite;

use std::{future::Future, pin::Pin};

use camino::Utf8PathBuf;
use headers::{ContentType, HeaderMapExt};
use http::Response;
use serde::Serialize;
use tower_service::Service;

pub use self::vite::Manifest as ViteManifest;

/// Service which renders an `index.html` based on the files in the manifest
#[derive(Debug, Clone)]
pub struct ViteManifestService<T> {
    manifest: Utf8PathBuf,
    assets_base: Utf8PathBuf,
    config: T,
}

impl<T> ViteManifestService<T> {
    #[must_use]
    pub const fn new(manifest: Utf8PathBuf, assets_base: Utf8PathBuf, config: T) -> Self {
        Self {
            manifest,
            assets_base,
            config,
        }
    }
}

impl<T, R> Service<R> for ViteManifestService<T>
where
    T: Clone + Serialize + Send + Sync + 'static,
{
    type Response = Response<String>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync + 'static>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: R) -> Self::Future {
        let manifest = self.manifest.clone();
        let assets_base = self.assets_base.clone();
        let config = self.config.clone();

        Box::pin(async move {
            // Read the manifest from disk
            let manifest = tokio::fs::read(manifest).await?;

            // Parse it
            let manifest: ViteManifest = serde_json::from_slice(&manifest)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

            // Render the HTML out of the manifest
            let html = manifest.render(&assets_base, &config).map_err(|error| {
                // The error is serialised to a string, because it is not 'static, as it
                // references the manifest
                let error = error.to_string();
                std::io::Error::new(std::io::ErrorKind::Other, error)
            })?;

            let mut response = Response::new(html);
            response.headers_mut().typed_insert(ContentType::html());

            Ok(response)
        })
    }
}
