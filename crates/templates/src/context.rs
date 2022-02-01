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

#![allow(clippy::trait_duplication_in_bounds)]

use mas_data_model::{
    errors::ErroredForm, AuthorizationGrant, BrowserSession, StorageBackend, User, UserEmail,
};
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

impl TemplateContext for () {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        Vec::new()
    }
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
    /// Constructs the context for the index page from the OIDC discovery
    /// document URL
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

/// Fields of the login form
#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoginFormField {
    /// The username field
    Username,

    /// The password field
    Password,
}

/// Context used in login and reauth screens, for the post-auth action to do
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContext {
    /// Continue an authorization grant
    ContinueAuthorizationGrant {
        /// The authorization grant that will be continued after authentication
        grant: AuthorizationGrant<()>,
    },
}

/// Context used by the `login.html` template
#[derive(Serialize)]
pub struct LoginContext {
    form: ErroredForm<LoginFormField>,
    next: Option<PostAuthContext>,
    register_link: String,
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
            register_link: "/register".to_string(),
        }]
    }
}

impl LoginContext {
    /// Add an error on the login form
    #[must_use]
    pub fn with_form_error(self, form: ErroredForm<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }

    /// Add a registration link to the context
    #[must_use]
    pub fn with_register_link(self, register_link: String) -> Self {
        Self {
            register_link,
            ..self
        }
    }
}

impl Default for LoginContext {
    fn default() -> Self {
        Self {
            form: ErroredForm::new(),
            next: None,
            register_link: "/register".to_string(),
        }
    }
}

/// Fields of the registration form
#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterFormField {
    /// The username field
    Username,

    /// The password field
    Password,

    /// The password confirmation field
    PasswordConfirm,
}

/// Context used by the `register.html` template
#[derive(Serialize)]
pub struct RegisterContext {
    form: ErroredForm<LoginFormField>,
    next: Option<PostAuthContext>,
    login_link: String,
}

impl TemplateContext for RegisterContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![RegisterContext {
            form: ErroredForm::default(),
            next: None,
            login_link: "/login".to_string(),
        }]
    }
}

impl RegisterContext {
    /// Add an error on the registration form
    #[must_use]
    pub fn with_form_error(self, form: ErroredForm<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }

    /// Add a login link to the context
    #[must_use]
    pub fn with_login_link(self, login_link: String) -> Self {
        Self { login_link, ..self }
    }
}

impl Default for RegisterContext {
    fn default() -> Self {
        Self {
            form: ErroredForm::new(),
            next: None,
            login_link: "/login".to_string(),
        }
    }
}

/// Fields of the reauthentication form
#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReauthFormField {
    /// The password field
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
    /// Add an error on the reauthentication form
    #[must_use]
    pub fn with_form_error(self, form: ErroredForm<ReauthFormField>) -> Self {
        Self { form, ..self }
    }

    /// Add a post authentication action to the context
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

/// Context used by the `account/index.html` template
#[derive(Serialize)]
pub struct AccountContext {
    active_sessions: usize,
    emails: Vec<UserEmail<()>>,
}

impl AccountContext {
    /// Constructs a context for the "my account" page
    #[must_use]
    pub fn new<T>(active_sessions: usize, emails: Vec<T>) -> Self
    where
        T: Into<UserEmail<()>>,
    {
        Self {
            active_sessions,
            emails: emails.into_iter().map(Into::into).collect(),
        }
    }
}

impl TemplateContext for AccountContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        let emails: Vec<UserEmail<()>> = UserEmail::samples();
        vec![Self::new(5, emails)]
    }
}

/// Context used by the `account/emails.html` template
#[derive(Serialize)]
#[serde(bound(serialize = "T: StorageBackend"))]
pub struct AccountEmailsContext<T: StorageBackend> {
    emails: Vec<UserEmail<T>>,
}

impl<T: StorageBackend> AccountEmailsContext<T> {
    /// Constructs a context for the email management page
    #[must_use]
    pub fn new(emails: Vec<UserEmail<T>>) -> Self {
        Self { emails }
    }
}

impl<T: StorageBackend> TemplateContext for AccountEmailsContext<T> {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        let emails: Vec<UserEmail<T>> = UserEmail::samples();
        vec![Self::new(emails)]
    }
}

/// Context used by the `emails/verification.{txt,html}` templates
#[derive(Serialize)]
pub struct EmailVerificationContext {
    user: User<()>,
    verification_link: Url,
}

impl EmailVerificationContext {
    /// Constructs a context for the verification email
    #[must_use]
    pub fn new(user: User<()>, verification_link: Url) -> Self {
        Self {
            user,
            verification_link,
        }
    }
}

impl TemplateContext for EmailVerificationContext {
    fn sample() -> Vec<Self>
    where
        Self: Sized,
    {
        User::samples()
            .into_iter()
            .map(|u| {
                Self::new(
                    u,
                    Url::parse("https://example.com/emails/verify?code=2134").unwrap(),
                )
            })
            .collect()
    }
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
    /// Constructs a context for the `form_post` response mode form
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
    /// Constructs a context for the error page
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the error code to the context
    #[must_use]
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    /// Add the error description to the context
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Add the error details to the context
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
