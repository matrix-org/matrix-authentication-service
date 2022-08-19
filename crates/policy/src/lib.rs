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
#![deny(clippy::all, clippy::str_to_string, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::io::Cursor;

use anyhow::bail;
use mas_data_model::{AuthorizationGrant, StorageBackend, User};
use oauth2_types::registration::ClientMetadata;
use opa_wasm::Runtime;
use serde::Deserialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use wasmtime::{Config, Engine, Module, Store};

const DEFAULT_POLICY: &[u8] = include_bytes!("../policies/policy.wasm");

#[must_use]
pub fn default_wasm_policy() -> impl AsyncRead + std::marker::Unpin {
    Cursor::new(DEFAULT_POLICY)
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read module")]
    Read(#[from] tokio::io::Error),

    #[error("failed to create WASM engine")]
    Engine(#[source] anyhow::Error),

    #[error("module compilation task crashed")]
    CompilationTask(#[from] tokio::task::JoinError),

    #[error("failed to compile WASM module")]
    Compilation(#[source] anyhow::Error),

    #[error("failed to instantiate a test instance")]
    Instantiate(#[source] anyhow::Error),

    #[error("could not load wasmtime cache configuration")]
    CacheSetup(#[source] anyhow::Error),
}

pub struct PolicyFactory {
    engine: Engine,
    module: Module,
    data: serde_json::Value,
    register_entrypoint: String,
    client_registration_entrypoint: String,
    authorization_grant_endpoint: String,
}

impl PolicyFactory {
    pub async fn load(
        mut source: impl AsyncRead + std::marker::Unpin,
        data: serde_json::Value,
        register_entrypoint: String,
        client_registration_entrypoint: String,
        authorization_grant_endpoint: String,
    ) -> Result<Self, LoadError> {
        let mut config = Config::default();
        config.async_support(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        config
            .cache_config_load_default()
            .map_err(LoadError::CacheSetup)?;

        let engine = Engine::new(&config).map_err(LoadError::Engine)?;

        // Read and compile the module
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).await?;
        // Compilation is CPU-bound, so spawn that in a blocking task
        let (engine, module) = tokio::task::spawn_blocking(move || {
            let module = Module::new(&engine, buf)?;
            anyhow::Ok((engine, module))
        })
        .await?
        .map_err(LoadError::Compilation)?;

        let factory = Self {
            engine,
            module,
            data,
            register_entrypoint,
            client_registration_entrypoint,
            authorization_grant_endpoint,
        };

        // Try to instanciate
        factory
            .instantiate()
            .await
            .map_err(LoadError::Instantiate)?;

        Ok(factory)
    }

    pub async fn load_default(data: serde_json::Value) -> Result<Self, LoadError> {
        Self::load(
            default_wasm_policy(),
            data,
            "register/violation".to_owned(),
            "client_registration/violation".to_owned(),
            "authorization_grant/violation".to_owned(),
        )
        .await
    }

    pub async fn instantiate(&self) -> Result<Policy, anyhow::Error> {
        let mut store = Store::new(&self.engine, ());
        let runtime = Runtime::new(&mut store, &self.module).await?;

        // Check that we have the required entrypoints
        let entrypoints = runtime.entrypoints();

        for e in [
            self.register_entrypoint.as_str(),
            self.client_registration_entrypoint.as_str(),
            self.authorization_grant_endpoint.as_str(),
        ] {
            if !entrypoints.contains(e) {
                bail!("missing entrypoint {e}")
            }
        }

        let instance = runtime.with_data(&mut store, &self.data).await?;

        Ok(Policy {
            store,
            instance,
            register_entrypoint: self.register_entrypoint.clone(),
            client_registration_entrypoint: self.client_registration_entrypoint.clone(),
            authorization_grant_endpoint: self.authorization_grant_endpoint.clone(),
        })
    }
}

#[derive(Deserialize, Debug)]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct EvaluationResult {
    #[serde(rename = "result")]
    pub violations: Vec<Violation>,
}

impl EvaluationResult {
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations.is_empty()
    }
}

pub struct Policy {
    store: Store<()>,
    instance: opa_wasm::Policy<opa_wasm::DefaultContext>,
    register_entrypoint: String,
    client_registration_entrypoint: String,
    authorization_grant_endpoint: String,
}

impl Policy {
    #[tracing::instrument(skip(self, password))]
    pub async fn evaluate_register(
        &mut self,
        username: &str,
        password: &str,
        email: &str,
    ) -> Result<EvaluationResult, anyhow::Error> {
        let input = serde_json::json!({
            "user": {
                "username": username,
                "password": password,
                "email": email
            }
        });

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.register_entrypoint, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    pub async fn evaluate_client_registration(
        &mut self,
        client_metadata: &ClientMetadata,
    ) -> Result<EvaluationResult, anyhow::Error> {
        let client_metadata = serde_json::to_value(client_metadata)?;
        let input = serde_json::json!({
            "client_metadata": client_metadata,
        });

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.client_registration_entrypoint,
                &input,
            )
            .await?;

        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    pub async fn evaluate_authorization_grant<T: StorageBackend + std::fmt::Debug>(
        &mut self,
        authorization_grant: &AuthorizationGrant<T>,
        user: &User<T>,
    ) -> Result<EvaluationResult, anyhow::Error> {
        let authorization_grant = serde_json::to_value(authorization_grant)?;
        let user = serde_json::to_value(user)?;
        let input = serde_json::json!({
            "authorization_grant": authorization_grant,
            "user": user,
        });

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.authorization_grant_endpoint, &input)
            .await?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register() {
        let factory = PolicyFactory::load_default(serde_json::json!({
            "allowed_domains": ["element.io", "*.element.io"],
            "banned_domains": ["staging.element.io"],
        }))
        .await
        .unwrap();

        let mut policy = factory.instantiate().await.unwrap();

        let res = policy
            .evaluate_register("hello", "hunter2", "hello@example.com")
            .await
            .unwrap();
        assert!(!res.valid());

        let res = policy
            .evaluate_register("hello", "hunter2", "hello@foo.element.io")
            .await
            .unwrap();
        assert!(res.valid());

        let res = policy
            .evaluate_register("hello", "hunter2", "hello@staging.element.io")
            .await
            .unwrap();
        assert!(!res.valid());
    }
}
