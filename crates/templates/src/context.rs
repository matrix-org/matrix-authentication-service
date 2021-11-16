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

//! Contexts used in templates

use mas_data_model::{errors::ErroredForm, AuthorizationGrant, BrowserSession, StorageBackend};
use oauth2_types::errors::OAuth2Error;
use serde::{ser::SerializeStruct, Serialize};
use url::Url;

/// Helper trait to construct context wrappers
pub trait TemplateContext: Serialize {
    /// Attach a user session to the template context
    fn with_session<S: StorageBackend>(
        self,
        current_session: BrowserSession<S>,
    ) -> WithSession<Self>
    where
        Self: Sized,
        BrowserSession<S>: Into<BrowserSession<()>>,
    {
        WithSession {
            current_session: current_session.into(),
            inner: self,
        }
    }

    /// Attach an optional user session to the template context
    fn maybe_with_session<S: StorageBackend>(
        self,
        current_session: Option<BrowserSession<S>>,
    ) -> WithOptionalSession<Self>
    where
        Self: Sized,
        BrowserSession<S>: Into<BrowserSession<()>>,
    {
        WithOptionalSession {
            current_session: current_session.map(Into::into),
            inner: self,
        }
    }

    /// Attach a CSRF token to the template context
    fn with_csrf(self, csrf_token: String) -> WithCsrf<Self>
    where
        Self: Sized,
    {
        // TODO: make this method use a CsrfToken again
        WithCsrf {
            csrf_token,
            inner: self,
        }
    }

    /// Generate sample values for this context type
    ///
    /// This is then used to check for template validity in unit tests and in
    /// the CLI (`cargo run -- templates check`)
    fn sample() -> Vec<Self>
    where
        Self: Sized;
}

/// Context with a CSRF token in it
#[derive(Serialize)]
pub struct WithCsrf<T> {
    csrf_token: String,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithCsrf<T> {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        T::sample()
            .into_iter()
            .map(|inner| WithCsrf {
                csrf_token: "fake_csrf_token".into(),
                inner,
            })
            .collect()
    }
}

/// Context with a user session in it
#[derive(Serialize)]
pub struct WithSession<T> {
    current_session: BrowserSession<()>,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithSession<T> {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        BrowserSession::samples()
            .into_iter()
            .flat_map(|session| {
                T::sample().into_iter().map(move |inner| WithSession {
                    current_session: session.clone(),
                    inner,
                })
            })
            .collect()
    }
}

/// Context with an optional user session in it
#[derive(Serialize)]
pub struct WithOptionalSession<T> {
    current_session: Option<BrowserSession<()>>,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithOptionalSession<T> {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        BrowserSession::samples()
            .into_iter()
            .map(Some) // Wrap all samples in an Option
            .chain(std::iter::once(None)) // Add the "None" option
            .flat_map(|session| {
                T::sample()
                    .into_iter()
                    .map(move |inner| WithOptionalSession {
                        current_session: session.clone(),
                        inner,
                    })
            })
            .collect()
    }
}

/// An empty context used for composition
pub struct EmptyContext;

impl Serialize for EmptyContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("EmptyContext", 0)?;
        // FIXME: for some reason, serde seems to not like struct flattening with empty
        // stuff
        s.serialize_field("__UNUSED", &())?;
        s.end()
    }
}

impl TemplateContext for EmptyContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        vec![EmptyContext]
    }
}

/// Context used by the `index.html` template
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

impl TemplateContext for IndexContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        vec![Self {
            discovery_url: "https://example.com/.well-known/openid-configuration"
                .parse()
                .unwrap(),
        }]
    }
}

#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoginFormField {
    Username,
    Password,
}

/// Context used in login and reauth screens, for the post-auth action to do
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContext {
    ContinueAuthorizationGrant { grant: AuthorizationGrant<()> },
}

/// Context used by the `login.html` template
#[derive(Serialize)]
pub struct LoginContext {
    form: ErroredForm<LoginFormField>,
    next: Option<PostAuthContext>,
}

impl TemplateContext for LoginContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![LoginContext {
            form: ErroredForm::default(),
            next: None,
        }]
    }
}

impl LoginContext {
    #[must_use]
    pub fn with_form_error(self, form: ErroredForm<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

impl Default for LoginContext {
    fn default() -> Self {
        Self {
            form: ErroredForm::new(),
            next: None,
        }
    }
}

#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReauthFormField {
    Password,
}

impl TemplateContext for ReauthContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![ReauthContext {
            form: ErroredForm::default(),
            next: None,
        }]
    }
}

impl ReauthContext {
    #[must_use]
    pub fn with_form_error(self, form: ErroredForm<ReauthFormField>) -> Self {
        Self { form, ..self }
    }

    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

impl Default for ReauthContext {
    fn default() -> Self {
        Self {
            form: ErroredForm::new(),
            next: None,
        }
    }
}

/// Context used by the `reauth.html` template
#[derive(Serialize)]
pub struct ReauthContext {
    form: ErroredForm<ReauthFormField>,
    next: Option<PostAuthContext>,
}

/// Context used by the `form_post.html` template
#[derive(Serialize)]
pub struct FormPostContext<T> {
    redirect_uri: Url,
    params: T,
}

impl<T: TemplateContext> TemplateContext for FormPostContext<T> {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        let sample_params = T::sample();
        sample_params
            .into_iter()
            .map(|params| FormPostContext {
                redirect_uri: "https://example.com/callback".parse().unwrap(),
                params,
            })
            .collect()
    }
}

impl<T> FormPostContext<T> {
    pub fn new(redirect_uri: Url, params: T) -> Self {
        Self {
            redirect_uri,
            params,
        }
    }
}

/// Context used by the `error.html` template
#[derive(Default, Serialize)]
pub struct ErrorContext {
    code: Option<&'static str>,
    description: Option<String>,
    details: Option<String>,
}

impl TemplateContext for ErrorContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        vec![
            Self::new()
                .with_code("sample_error")
                .with_description("A fancy description".into())
                .with_details("Something happened".into()),
            Self::new().with_code("another_error"),
            Self::new(),
        ]
    }
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
