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

use std::{ops::Deref, sync::Arc};

use anyhow::Context as _;
use serde::Serialize;
use tera::{Context, Tera};
use tracing::info;

use crate::{filters::CsrfToken, storage::SessionInfo};

#[derive(Clone)]
pub struct Templates(Arc<Tera>);

impl Templates {
    pub fn load() -> Result<Self, tera::Error> {
        let path = format!("{}/templates/**/*.{{html,txt}}", env!("CARGO_MANIFEST_DIR"));
        info!(%path, "Loading templates");
        let tera = Tera::new(&path)?;
        Ok(Self(Arc::new(tera)))
    }
}

impl Deref for Templates {
    type Target = Tera;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Serialize, Default)]
pub struct CommonContext {
    csrf_token: Option<String>,
    current_session: Option<SessionInfo>,
}

impl CommonContext {
    pub fn with_csrf_token(self, token: &CsrfToken) -> Self {
        Self {
            csrf_token: Some(token.form_value()),
            ..self
        }
    }

    pub fn maybe_with_session(self, current_session: Option<SessionInfo>) -> Self {
        Self {
            current_session,
            ..self
        }
    }

    #[allow(dead_code)]
    pub fn with_session(self, current_session: SessionInfo) -> Self {
        self.maybe_with_session(Some(current_session))
    }

    pub fn finish(self) -> anyhow::Result<Context> {
        Context::from_serialize(&self).context("could not serialize common context for templates")
    }
}
