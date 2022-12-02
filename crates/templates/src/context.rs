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

#![allow(clippy::trait_duplication_in_bounds, clippy::type_repetition_in_bounds)]

use chrono::Utc;
use mas_data_model::{
    AuthorizationGrant, BrowserSession, CompatSsoLogin, CompatSsoLoginState, StorageBackend,
    UpstreamOAuthLink, UpstreamOAuthProvider, User, UserEmail, UserEmailVerification,
};
use mas_router::{PostAuthAction, Route};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use ulid::Ulid;
use url::Url;

use crate::{FormField, FormState};

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
    fn with_csrf<C>(self, csrf_token: C) -> WithCsrf<Self>
    where
        Self: Sized,
        C: ToString,
    {
        // TODO: make this method use a CsrfToken again
        WithCsrf {
            csrf_token: csrf_token.to_string(),
            inner: self,
        }
    }

    /// Generate sample values for this context type
    ///
    /// This is then used to check for template validity in unit tests and in
    /// the CLI (`cargo run -- templates check`)
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized;
}

impl TemplateContext for () {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
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
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        T::sample(now)
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
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now)
            .into_iter()
            .flat_map(|session| {
                T::sample(now).into_iter().map(move |inner| WithSession {
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
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now)
            .into_iter()
            .map(Some) // Wrap all samples in an Option
            .chain(std::iter::once(None)) // Add the "None" option
            .flat_map(|session| {
                T::sample(now)
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
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
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
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoginFormField {
    /// The username field
    Username,

    /// The password field
    Password,
}

impl FormField for LoginFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username => true,
            Self::Password => false,
        }
    }
}

/// Context used in login and reauth screens, for the post-auth action to do
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContext {
    /// Continue an authorization grant
    ContinueAuthorizationGrant {
        /// The authorization grant that will be continued after authentication
        grant: Box<AuthorizationGrant<()>>,
    },

    /// Continue legacy login
    /// TODO: add the login context in there
    ContinueCompatSsoLogin {
        /// The compat SSO login request
        login: Box<CompatSsoLogin<()>>,
    },

    /// Change the account password
    ChangePassword,

    /// Link an upstream account
    LinkUpstream {
        /// The upstream provider
        provider: Box<UpstreamOAuthProvider>,

        /// The link
        link: Box<UpstreamOAuthLink>,
    },
}

/// Context used by the `login.html` template
#[derive(Serialize, Default)]
pub struct LoginContext {
    form: FormState<LoginFormField>,
    next: Option<PostAuthContext>,
    providers: Vec<UpstreamOAuthProvider>,
    register_link: String,
}

impl TemplateContext for LoginContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![LoginContext {
            form: FormState::default(),
            next: None,
            providers: Vec::new(),
            register_link: "/register".to_owned(),
        }]
    }
}

impl LoginContext {
    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Set the upstream OAuth 2.0 providers
    #[must_use]
    pub fn with_upstrem_providers(self, providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self { providers, ..self }
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

/// Fields of the registration form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterFormField {
    /// The username field
    Username,

    /// The email field
    Email,

    /// The password field
    Password,

    /// The password confirmation field
    PasswordConfirm,
}

impl FormField for RegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username | Self::Email => true,
            Self::Password | Self::PasswordConfirm => false,
        }
    }
}

/// Context used by the `register.html` template
#[derive(Serialize, Default)]
pub struct RegisterContext {
    form: FormState<RegisterFormField>,
    next: Option<PostAuthContext>,
    login_link: String,
}

impl TemplateContext for RegisterContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![RegisterContext {
            form: FormState::default(),
            next: None,
            login_link: "/login".to_owned(),
        }]
    }
}

impl RegisterContext {
    /// Add an error on the registration form
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterFormField>) -> Self {
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

/// Context used by the `consent.html` template
#[derive(Serialize)]
pub struct ConsentContext {
    grant: AuthorizationGrant<()>,
    action: PostAuthAction,
}

impl TemplateContext for ConsentContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO
        vec![]
    }
}

impl ConsentContext {
    /// Constructs a context for the client consent page
    #[must_use]
    pub fn new<T>(grant: T, action: PostAuthAction) -> Self
    where
        T: Into<AuthorizationGrant<()>>,
    {
        Self {
            grant: grant.into(),
            action,
        }
    }
}

/// Context used by the `policy_violation.html` template
#[derive(Serialize)]
pub struct PolicyViolationContext {
    grant: AuthorizationGrant<()>,
    action: PostAuthAction,
}

impl TemplateContext for PolicyViolationContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO
        vec![]
    }
}

impl PolicyViolationContext {
    /// Constructs a context for the policy violation page
    #[must_use]
    pub fn new<T>(grant: T, action: PostAuthAction) -> Self
    where
        T: Into<AuthorizationGrant<()>>,
    {
        Self {
            grant: grant.into(),
            action,
        }
    }
}

/// Fields of the reauthentication form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReauthFormField {
    /// The password field
    Password,
}

impl FormField for ReauthFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Password => false,
        }
    }
}

/// Context used by the `reauth.html` template
#[derive(Serialize, Default)]
pub struct ReauthContext {
    form: FormState<ReauthFormField>,
    next: Option<PostAuthContext>,
    action: Option<PostAuthAction>,
}

impl TemplateContext for ReauthContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![ReauthContext {
            form: FormState::default(),
            next: None,
            action: None,
        }]
    }
}

impl ReauthContext {
    /// Add an error on the reauthentication form
    #[must_use]
    pub fn with_form_state(self, form: FormState<ReauthFormField>) -> Self {
        Self { form, ..self }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext, action: PostAuthAction) -> Self {
        Self {
            next: Some(next),
            action: Some(action),
            ..self
        }
    }
}

/// Context used by the `sso.html` template
#[derive(Serialize)]
pub struct CompatSsoContext {
    login: CompatSsoLogin<()>,
    action: PostAuthAction,
}

impl TemplateContext for CompatSsoContext {
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![CompatSsoContext {
            login: CompatSsoLogin {
                data: (),
                redirect_uri: Url::parse("https://app.element.io/").unwrap(),
                login_token: "abcdefghijklmnopqrstuvwxyz012345".into(),
                created_at: now,
                state: CompatSsoLoginState::Pending,
            },
            action: PostAuthAction::ContinueCompatSsoLogin { data: Ulid::nil() },
        }]
    }
}

impl CompatSsoContext {
    /// Constructs a context for the legacy SSO login page
    #[must_use]
    pub fn new<T>(login: T, action: PostAuthAction) -> Self
    where
        T: Into<CompatSsoLogin<()>>,
    {
        Self {
            login: login.into(),
            action,
        }
    }
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
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        let emails: Vec<UserEmail<()>> = UserEmail::samples(now);
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
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        let emails: Vec<UserEmail<T>> = UserEmail::samples(now);
        vec![Self::new(emails)]
    }
}

/// Context used by the `emails/verification.{txt,html,subject}` templates
#[derive(Serialize)]
pub struct EmailVerificationContext {
    user: User<()>,
    verification: UserEmailVerification<()>,
}

impl EmailVerificationContext {
    /// Constructs a context for the verification email
    #[must_use]
    pub fn new(user: User<()>, verification: UserEmailVerification<()>) -> Self {
        Self { user, verification }
    }
}

impl TemplateContext for EmailVerificationContext {
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        User::samples(now)
            .into_iter()
            .map(|user| {
                let email = UserEmail {
                    data: (),
                    email: "foobar@example.com".to_owned(),
                    created_at: now,
                    confirmed_at: None,
                };

                let verification = UserEmailVerification {
                    data: (),
                    code: "123456".to_owned(),
                    email,
                    created_at: now,
                    state: mas_data_model::UserEmailVerificationState::Valid,
                };

                Self { user, verification }
            })
            .collect()
    }
}

/// Fields of the email verification form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmailVerificationFormField {
    /// The code field
    Code,
}

impl FormField for EmailVerificationFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Code => true,
        }
    }
}

/// Context used by the `pages/account/verify.html` templates
#[derive(Serialize)]
pub struct EmailVerificationPageContext {
    form: FormState<EmailVerificationFormField>,
    email: UserEmail<()>,
}

impl EmailVerificationPageContext {
    /// Constructs a context for the email verification page
    #[must_use]
    pub fn new<T>(email: T) -> Self
    where
        T: Into<UserEmail<()>>,
    {
        Self {
            form: FormState::default(),
            email: email.into(),
        }
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<EmailVerificationFormField>) -> Self {
        Self { form, ..self }
    }
}

impl TemplateContext for EmailVerificationPageContext {
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        let email = UserEmail {
            data: (),
            email: "foobar@example.com".to_owned(),
            created_at: now,
            confirmed_at: None,
        };

        vec![Self {
            form: FormState::default(),
            email,
        }]
    }
}

/// Fields of the account email add form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmailAddFormField {
    /// The email
    Email,
}

impl FormField for EmailAddFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Email => true,
        }
    }
}

/// Context used by the `pages/account/verify.html` templates
#[derive(Serialize, Default)]
pub struct EmailAddContext {
    form: FormState<EmailAddFormField>,
}

impl EmailAddContext {
    /// Constructs a context for the email add page
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(form: FormState<EmailAddFormField>) -> Self {
        Self { form }
    }
}

impl TemplateContext for EmailAddContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![Self::default()]
    }
}

/// Context used by the `pages/upstream_oauth2/{link_mismatch,do_login}.html`
/// templates
#[derive(Serialize)]
pub struct UpstreamExistingLinkContext {
    linked_user: User<()>,
}

impl UpstreamExistingLinkContext {
    /// Constructs a new context with an existing linked user
    pub fn new<T>(linked_user: T) -> Self
    where
        T: Into<User<()>>,
    {
        Self {
            linked_user: linked_user.into(),
        }
    }
}

impl TemplateContext for UpstreamExistingLinkContext {
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        User::samples(now)
            .into_iter()
            .map(|linked_user| Self { linked_user })
            .collect()
    }
}

/// Context used by the `pages/upstream_oauth2/suggest_link.html`
/// templates
#[derive(Serialize)]
pub struct UpstreamSuggestLink {
    post_logout_action: PostAuthAction,
}

impl UpstreamSuggestLink {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(link_id: Ulid) -> Self {
        let post_logout_action = PostAuthAction::LinkUpstream { id: link_id };
        Self { post_logout_action }
    }
}

impl TemplateContext for UpstreamSuggestLink {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![Self::new(Ulid::nil())]
    }
}

/// Context used by the `pages/upstream_oauth2/do_register.html`
/// templates
#[derive(Serialize)]
pub struct UpstreamRegister {
    login_link: String,
}

impl UpstreamRegister {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(link_id: Ulid) -> Self {
        let action = PostAuthAction::LinkUpstream { id: link_id };
        let login_link = mas_router::Login::and_then(action).relative_url().into();
        Self { login_link }
    }
}

impl TemplateContext for UpstreamRegister {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![Self::new(Ulid::nil())]
    }
}

/// Context used by the `form_post.html` template
#[derive(Serialize)]
pub struct FormPostContext<T> {
    redirect_uri: Url,
    params: T,
}

impl<T: TemplateContext> TemplateContext for FormPostContext<T> {
    fn sample(now: chrono::DateTime<Utc>) -> Vec<Self>
    where
        Self: Sized,
    {
        let sample_params = T::sample(now);
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
#[derive(Default, Serialize, Debug, Clone)]
pub struct ErrorContext {
    code: Option<&'static str>,
    description: Option<String>,
    details: Option<String>,
}

impl TemplateContext for ErrorContext {
    fn sample(_now: chrono::DateTime<Utc>) -> Vec<Self>
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
