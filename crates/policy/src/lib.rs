// Copyright 2022-2023 The Matrix.org Foundation C.I.C.
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

pub mod model;

use mas_data_model::{AuthorizationGrant, Client, DeviceCodeGrant, User};
use oauth2_types::{registration::VerifiedClientMetadata, scope::Scope};
use opa_wasm::Runtime;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use wasmtime::{Config, Engine, Module, Store};

use self::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, PasswordInput, RegisterInput,
};
pub use self::model::{EvaluationResult, Violation};
use crate::model::GrantType;

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
    Instantiate(#[source] InstantiateError),

    #[cfg(feature = "cache")]
    #[error("could not load wasmtime cache configuration")]
    CacheSetup(#[source] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum InstantiateError {
    #[error("failed to create WASM runtime")]
    Runtime(#[source] anyhow::Error),

    #[error("missing entrypoint {entrypoint}")]
    MissingEntrypoint { entrypoint: String },

    #[error("failed to load policy data")]
    LoadData(#[source] anyhow::Error),
}

/// Holds the entrypoint of each policy
#[derive(Debug, Clone)]
pub struct Entrypoints {
    pub register: String,
    pub client_registration: String,
    pub authorization_grant: String,
    pub email: String,
    pub password: String,
}

impl Entrypoints {
    fn all(&self) -> [&str; 5] {
        [
            self.register.as_str(),
            self.client_registration.as_str(),
            self.authorization_grant.as_str(),
            self.email.as_str(),
            self.password.as_str(),
        ]
    }
}

pub struct PolicyFactory {
    engine: Engine,
    module: Module,
    data: serde_json::Value,
    entrypoints: Entrypoints,
}

impl PolicyFactory {
    #[tracing::instrument(name = "policy.load", skip(source), err)]
    pub async fn load(
        mut source: impl AsyncRead + std::marker::Unpin,
        data: serde_json::Value,
        entrypoints: Entrypoints,
    ) -> Result<Self, LoadError> {
        let mut config = Config::default();
        config.async_support(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        #[cfg(feature = "cache")]
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
            entrypoints,
        };

        // Try to instantiate
        factory
            .instantiate()
            .await
            .map_err(LoadError::Instantiate)?;

        Ok(factory)
    }

    #[tracing::instrument(name = "policy.instantiate", skip_all, err)]
    pub async fn instantiate(&self) -> Result<Policy, InstantiateError> {
        let mut store = Store::new(&self.engine, ());
        let runtime = Runtime::new(&mut store, &self.module)
            .await
            .map_err(InstantiateError::Runtime)?;

        // Check that we have the required entrypoints
        let policy_entrypoints = runtime.entrypoints();

        for e in self.entrypoints.all() {
            if !policy_entrypoints.contains(e) {
                return Err(InstantiateError::MissingEntrypoint {
                    entrypoint: e.to_owned(),
                });
            }
        }

        let instance = runtime
            .with_data(&mut store, &self.data)
            .await
            .map_err(InstantiateError::LoadData)?;

        Ok(Policy {
            store,
            instance,
            entrypoints: self.entrypoints.clone(),
        })
    }
}

pub struct Policy {
    store: Store<()>,
    instance: opa_wasm::Policy<opa_wasm::DefaultContext>,
    entrypoints: Entrypoints,
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] anyhow::Error),
}

impl Policy {
    #[tracing::instrument(
        name = "policy.evaluate_email",
        skip_all,
        fields(
            input.email = email,
        ),
        err,
    )]
    pub async fn evaluate_email(
        &mut self,
        email: &str,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = EmailInput { email };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.email, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(name = "policy.evaluate_password", skip_all, err)]
    pub async fn evaluate_password(
        &mut self,
        password: &str,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = PasswordInput { password };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.password, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.register",
        skip_all,
        fields(
            input.registration_method = "password",
            input.user.username = username,
            input.user.email = email,
        ),
        err,
    )]
    pub async fn evaluate_register(
        &mut self,
        username: &str,
        password: &str,
        email: &str,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = RegisterInput::Password {
            username,
            password,
            email,
        };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.register, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.upstream_oauth_register",
        skip_all,
        fields(
            input.registration_method = "password",
            input.user.username = username,
            input.user.email = email,
        ),
        err,
    )]
    pub async fn evaluate_upstream_oauth_register(
        &mut self,
        username: &str,
        email: Option<&str>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = RegisterInput::UpstreamOAuth2 { username, email };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.register, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    pub async fn evaluate_client_registration(
        &mut self,
        client_metadata: &VerifiedClientMetadata,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = ClientRegistrationInput { client_metadata };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.client_registration,
                &input,
            )
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.authorization_grant",
        skip_all,
        fields(
            input.authorization_grant.id = %authorization_grant.id,
            input.scope = %authorization_grant.scope,
            input.client.id = %client.id,
            input.user.id = %user.id,
        ),
        err,
    )]
    pub async fn evaluate_authorization_grant(
        &mut self,
        authorization_grant: &AuthorizationGrant,
        client: &Client,
        user: &User,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = AuthorizationGrantInput {
            user: Some(user),
            client,
            scope: &authorization_grant.scope,
            grant_type: GrantType::AuthorizationCode,
        };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.authorization_grant,
                &input,
            )
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.client_credentials_grant",
        skip_all,
        fields(
            input.scope = %scope,
            input.client.id = %client.id,
        ),
        err,
    )]
    pub async fn evaluate_client_credentials_grant(
        &mut self,
        scope: &Scope,
        client: &Client,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = AuthorizationGrantInput {
            user: None,
            client,
            scope,
            grant_type: GrantType::ClientCredentials,
        };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.authorization_grant,
                &input,
            )
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.device_code_grant",
        skip_all,
        fields(
            input.device_code_grant.id = %device_code_grant.id,
            input.scope = %device_code_grant.scope,
            input.client.id = %client.id,
            input.user.id = %user.id,
        ),
        err,
    )]
    pub async fn evaluate_device_code_grant(
        &mut self,
        device_code_grant: &DeviceCodeGrant,
        client: &Client,
        user: &User,
    ) -> Result<EvaluationResult, EvaluationError> {
        let input = AuthorizationGrantInput {
            user: Some(user),
            client,
            scope: &device_code_grant.scope,
            grant_type: GrantType::DeviceCode,
        };

        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.authorization_grant,
                &input,
            )
            .await?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register() {
        let data = serde_json::json!({
            "allowed_domains": ["element.io", "*.element.io"],
            "banned_domains": ["staging.element.io"],
        });

        #[allow(clippy::disallowed_types)]
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("policies")
            .join("policy.wasm");

        let file = tokio::fs::File::open(path).await.unwrap();

        let entrypoints = Entrypoints {
            register: "register/violation".to_owned(),
            client_registration: "client_registration/violation".to_owned(),
            authorization_grant: "authorization_grant/violation".to_owned(),
            email: "email/violation".to_owned(),
            password: "password/violation".to_owned(),
        };

        let factory = PolicyFactory::load(file, data, entrypoints).await.unwrap();

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
