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

use anyhow::bail;
use oauth2_types::registration::ClientMetadata;
use opa_wasm::Runtime;
use serde::Deserialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use wasmtime::{Config, Engine, Module, Store};

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
}

pub struct PolicyFactory {
    engine: Engine,
    module: Module,
    data: serde_json::Value,
    login_entrypoint: String,
    register_entrypoint: String,
    client_registration_entrypoint: String,
}

impl PolicyFactory {
    pub async fn load(
        mut source: impl AsyncRead + std::marker::Unpin,
        data: serde_json::Value,
        login_entrypoint: String,
        register_entrypoint: String,
        client_registration_entrypoint: String,
    ) -> Result<Self, LoadError> {
        let mut config = Config::default();
        config.async_support(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        let engine = Engine::new(&config).map_err(LoadError::Engine)?;
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).await?;
        let (engine, module) = tokio::task::spawn_blocking(move || {
            let module = Module::new(&engine, buf);
            (engine, module)
        })
        .await?;
        let module = module.map_err(LoadError::Compilation)?;

        Ok(Self {
            engine,
            module,
            data,
            login_entrypoint,
            register_entrypoint,
            client_registration_entrypoint,
        })
    }

    pub async fn instanciate(&self) -> Result<Policy, anyhow::Error> {
        let mut store = Store::new(&self.engine, ());
        let runtime = Runtime::new(&mut store, &self.module).await?;

        // Check that we have the required entrypoints
        let entrypoints = runtime.entrypoints();

        for e in [
            self.login_entrypoint.as_str(),
            self.register_entrypoint.as_str(),
        ] {
            if !entrypoints.contains(e) {
                bail!("missing entrypoint {e}")
            }
        }

        let instance = runtime.with_data(&mut store, &self.data).await?;

        Ok(Policy {
            store,
            instance,
            login_entrypoint: self.login_entrypoint.clone(),
            register_entrypoint: self.register_entrypoint.clone(),
            client_registration_entrypoint: self.client_registration_entrypoint.clone(),
        })
    }
}

#[derive(Deserialize)]
struct EvaluationResult {
    result: bool,
}

pub struct Policy {
    store: Store<()>,
    instance: opa_wasm::Policy,
    login_entrypoint: String,
    register_entrypoint: String,
    client_registration_entrypoint: String,
}

impl Policy {
    pub async fn evaluate_login(
        &mut self,
        user: &mas_data_model::User<()>,
    ) -> Result<bool, anyhow::Error> {
        let user = serde_json::to_value(user)?;
        let input = serde_json::json!({ "user": user });

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.login_entrypoint, &input)
            .await?;

        Ok(res.result)
    }

    pub async fn evaluate_register(
        &mut self,
        username: &str,
        email: &str,
    ) -> Result<bool, anyhow::Error> {
        let input = serde_json::json!({
            "user": {
                "username": username,
                "email": email
            }
        });

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.register_entrypoint, &input)
            .await?;

        Ok(res.result)
    }

    pub async fn evaluate_client_registration(
        &mut self,
        client_metadata: &ClientMetadata,
    ) -> Result<bool, anyhow::Error> {
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

        Ok(res.result)
    }
}
