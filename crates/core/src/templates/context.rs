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

use oauth2_types::errors::OAuth2Error;
use serde::Serialize;
use url::Url;

use crate::{errors::ErroredForm, filters::CsrfToken, storage::SessionInfo};

/// Helper trait to construct context wrappers
pub trait TemplateContext: Sized {
    fn with_session(self, current_session: SessionInfo) -> WithSession<Self> {
        WithSession {
            current_session,
            inner: self,
        }
    }

    fn maybe_with_session(self, current_session: Option<SessionInfo>) -> WithOptionalSession<Self> {
        WithOptionalSession {
            current_session,
            inner: self,
        }
    }

    fn with_csrf(self, token: &CsrfToken) -> WithCsrf<Self> {
        WithCsrf {
            csrf_token: token.form_value(),
            inner: self,
        }
    }
}

impl TemplateContext for () {}
impl TemplateContext for IndexContext {}
impl TemplateContext for LoginContext {}
impl<T: Sized> TemplateContext for FormPostContext<T> {}
impl<T: Sized> TemplateContext for WithSession<T> {}
impl<T: Sized> TemplateContext for WithOptionalSession<T> {}
impl<T: Sized> TemplateContext for WithCsrf<T> {}

/// Context with a CSRF token in it
#[derive(Serialize)]
pub struct WithCsrf<T> {
    csrf_token: String,

    #[serde(flatten)]
    inner: T,
}

/// Context with a user session in it
#[derive(Serialize)]
pub struct WithSession<T> {
    current_session: SessionInfo,

    #[serde(flatten)]
    inner: T,
}

/// Context with an optional user session in it
#[derive(Serialize)]
pub struct WithOptionalSession<T> {
    current_session: Option<SessionInfo>,

    #[serde(flatten)]
    inner: T,
}

// Context used by the `index.html` template
#[derive(Serialize)]
pub struct IndexContext {
    discovery_url: Url,
}

impl IndexContext {
    #[must_use]
    pub fn new(discovery_url: Url) -> Self {
        Self { discovery_url }
    }
}

#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoginFormField {
    Username,
    Password,
}

#[derive(Serialize)]
pub struct LoginContext {
    form: ErroredForm<LoginFormField>,
}

impl LoginContext {
    #[must_use]
    pub fn with_form_error(form: ErroredForm<LoginFormField>) -> Self {
        Self { form }
    }
}

impl Default for LoginContext {
    fn default() -> Self {
        Self {
            form: ErroredForm::new(),
        }
    }
}

/// Context used by the `form_post.html` template
#[derive(Serialize)]
pub struct FormPostContext<T> {
    redirect_uri: Url,
    params: T,
}

impl<T> FormPostContext<T> {
    pub fn new(redirect_uri: Url, params: T) -> Self {
        Self {
            redirect_uri,
            params,
        }
    }
}

#[derive(Default, Serialize)]
pub struct ErrorContext {
    code: Option<&'static str>,
    description: Option<String>,
    details: Option<String>,
}

impl ErrorContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
}

impl From<Box<dyn OAuth2Error>> for ErrorContext {
    fn from(err: Box<dyn OAuth2Error>) -> Self {
        let mut ctx = ErrorContext::new().with_code(err.error());
        if let Some(desc) = err.description() {
            ctx = ctx.with_description(desc);
        }
        ctx
    }
}
