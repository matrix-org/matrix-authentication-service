// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

mod branding;

use std::{
    fmt::Formatter,
    net::{IpAddr, Ipv4Addr},
};

use chrono::{DateTime, Duration, Utc};
use http::{Method, Uri, Version};
use mas_data_model::{
    AuthorizationGrant, BrowserSession, Client, CompatSsoLogin, CompatSsoLoginState,
    DeviceCodeGrant, UpstreamOAuthLink, UpstreamOAuthProvider, User, UserEmail,
    UserEmailVerification,
};
use mas_i18n::DataLocale;
use mas_router::{Account, GraphQL, PostAuthAction, UrlBuilder};
use oauth2_types::scope::OPENID;
use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use ulid::Ulid;
use url::Url;

pub use self::branding::SiteBranding;
use crate::{FieldError, FormField, FormState};

/// Helper trait to construct context wrappers
pub trait TemplateContext: Serialize {
    /// Attach a user session to the template context
    fn with_session(self, current_session: BrowserSession) -> WithSession<Self>
    where
        Self: Sized,
    {
        WithSession {
            current_session,
            inner: self,
        }
    }

    /// Attach an optional user session to the template context
    fn maybe_with_session(
        self,
        current_session: Option<BrowserSession>,
    ) -> WithOptionalSession<Self>
    where
        Self: Sized,
    {
        WithOptionalSession {
            current_session,
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

    /// Attach a language to the template context
    fn with_language(self, lang: DataLocale) -> WithLanguage<Self>
    where
        Self: Sized,
    {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }

    /// Generate sample values for this context type
    ///
    /// This is then used to check for template validity in unit tests and in
    /// the CLI (`cargo run -- templates check`)
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized;
}

impl TemplateContext for () {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        Vec::new()
    }
}

/// Context with a specified locale in it
#[derive(Serialize, Debug)]
pub struct WithLanguage<T> {
    lang: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithLanguage<T> {
    /// Get the language of this context
    pub fn language(&self) -> &str {
        &self.lang
    }
}

impl<T> std::ops::Deref for WithLanguage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: TemplateContext> TemplateContext for WithLanguage<T> {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        T::sample(now, rng)
            .into_iter()
            .map(|inner| WithLanguage {
                lang: "en".into(),
                inner,
            })
            .collect()
    }
}

/// Context with a CSRF token in it
#[derive(Serialize, Debug)]
pub struct WithCsrf<T> {
    csrf_token: String,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithCsrf<T> {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        T::sample(now, rng)
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
    current_session: BrowserSession,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithSession<T> {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now, rng)
            .into_iter()
            .flat_map(|session| {
                T::sample(now, rng)
                    .into_iter()
                    .map(move |inner| WithSession {
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
    current_session: Option<BrowserSession>,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithOptionalSession<T> {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now, rng)
            .into_iter()
            .map(Some) // Wrap all samples in an Option
            .chain(std::iter::once(None)) // Add the "None" option
            .flat_map(|session| {
                T::sample(now, rng)
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
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
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
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
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

/// Config used by the frontend app
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    root: String,
    graphql_endpoint: String,
}

/// Context used by the `app.html` template
#[derive(Serialize)]
pub struct AppContext {
    app_config: AppConfig,
}

impl AppContext {
    /// Constructs the context given the [`UrlBuilder`]
    #[must_use]
    pub fn from_url_builder(url_builder: &UrlBuilder) -> Self {
        let root = url_builder.relative_url_for(&Account::default());
        let graphql_endpoint = url_builder.relative_url_for(&GraphQL);
        Self {
            app_config: AppConfig {
                root,
                graphql_endpoint,
            },
        }
    }
}

impl TemplateContext for AppContext {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        vec![Self::from_url_builder(&url_builder)]
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

/// Inner context used in login and reauth screens. See [`PostAuthContext`].
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContextInner {
    /// Continue an authorization grant
    ContinueAuthorizationGrant {
        /// The authorization grant that will be continued after authentication
        grant: Box<AuthorizationGrant>,
    },

    /// Continue a device code grant
    ContinueDeviceCodeGrant {
        /// The device code grant that will be continued after authentication
        grant: Box<DeviceCodeGrant>,
    },

    /// Continue legacy login
    /// TODO: add the login context in there
    ContinueCompatSsoLogin {
        /// The compat SSO login request
        login: Box<CompatSsoLogin>,
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

    /// Go to the account management page
    ManageAccount,
}

/// Context used in login and reauth screens, for the post-auth action to do
#[derive(Serialize)]
pub struct PostAuthContext {
    /// The post auth action params from the URL
    pub params: PostAuthAction,

    /// The loaded post auth context
    #[serde(flatten)]
    pub ctx: PostAuthContextInner,
}

/// Context used by the `login.html` template
#[derive(Serialize, Default)]
pub struct LoginContext {
    form: FormState<LoginFormField>,
    next: Option<PostAuthContext>,
    password_disabled: bool,
    providers: Vec<UpstreamOAuthProvider>,
}

impl TemplateContext for LoginContext {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![
            LoginContext {
                form: FormState::default(),
                next: None,
                password_disabled: true,
                providers: Vec::new(),
            },
            LoginContext {
                form: FormState::default(),
                next: None,
                password_disabled: false,
                providers: Vec::new(),
            },
            LoginContext {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Required)
                    .with_error_on_field(
                        LoginFormField::Password,
                        FieldError::Policy {
                            message: "password too short".to_owned(),
                        },
                    ),
                next: None,
                password_disabled: false,
                providers: Vec::new(),
            },
            LoginContext {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Exists),
                next: None,
                password_disabled: false,
                providers: Vec::new(),
            },
        ]
    }
}

impl LoginContext {
    /// Set whether password login is enabled or not
    #[must_use]
    pub fn with_password_login(self, enabled: bool) -> Self {
        Self {
            password_disabled: !enabled,
            ..self
        }
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Set the upstream OAuth 2.0 providers
    #[must_use]
    pub fn with_upstream_providers(self, providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self { providers, ..self }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, context: PostAuthContext) -> Self {
        Self {
            next: Some(context),
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
}

impl TemplateContext for RegisterContext {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![RegisterContext {
            form: FormState::default(),
            next: None,
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
}

/// Context used by the `consent.html` template
#[derive(Serialize)]
pub struct ConsentContext {
    grant: AuthorizationGrant,
    client: Client,
    action: PostAuthAction,
}

impl TemplateContext for ConsentContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        Client::samples(now, rng)
            .into_iter()
            .map(|client| {
                let mut grant = AuthorizationGrant::sample(now, rng);
                let action = PostAuthAction::continue_grant(grant.id);
                // XXX
                grant.client_id = client.id;
                Self {
                    grant,
                    client,
                    action,
                }
            })
            .collect()
    }
}

impl ConsentContext {
    /// Constructs a context for the client consent page
    #[must_use]
    pub fn new(grant: AuthorizationGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant,
            client,
            action,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "grant_type")]
enum PolicyViolationGrant {
    #[serde(rename = "authorization_code")]
    Authorization(AuthorizationGrant),
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),
}

/// Context used by the `policy_violation.html` template
#[derive(Serialize)]
pub struct PolicyViolationContext {
    grant: PolicyViolationGrant,
    client: Client,
    action: PostAuthAction,
}

impl TemplateContext for PolicyViolationContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        Client::samples(now, rng)
            .into_iter()
            .flat_map(|client| {
                let mut grant = AuthorizationGrant::sample(now, rng);
                // XXX
                grant.client_id = client.id;

                let authorization_grant =
                    PolicyViolationContext::for_authorization_grant(grant, client.clone());
                let device_code_grant = PolicyViolationContext::for_device_code_grant(
                    DeviceCodeGrant {
                        id: Ulid::from_datetime_with_source(now.into(), rng),
                        state: mas_data_model::DeviceCodeGrantState::Pending,
                        client_id: client.id,
                        scope: [OPENID].into_iter().collect(),
                        user_code: Alphanumeric.sample_string(rng, 6).to_uppercase(),
                        device_code: Alphanumeric.sample_string(rng, 32),
                        created_at: now - Duration::minutes(5),
                        expires_at: now + Duration::minutes(25),
                        ip_address: None,
                        user_agent: None,
                    },
                    client,
                );

                [authorization_grant, device_code_grant]
            })
            .collect()
    }
}

impl PolicyViolationContext {
    /// Constructs a context for the policy violation page for an authorization
    /// grant
    #[must_use]
    pub const fn for_authorization_grant(grant: AuthorizationGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::Authorization(grant),
            client,
            action,
        }
    }

    /// Constructs a context for the policy violation page for a device code
    /// grant
    #[must_use]
    pub const fn for_device_code_grant(grant: DeviceCodeGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_device_code_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::DeviceCode(grant),
            client,
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
}

impl TemplateContext for ReauthContext {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        vec![ReauthContext {
            form: FormState::default(),
            next: None,
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
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

/// Context used by the `sso.html` template
#[derive(Serialize)]
pub struct CompatSsoContext {
    login: CompatSsoLogin,
    action: PostAuthAction,
}

impl TemplateContext for CompatSsoContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        vec![CompatSsoContext::new(CompatSsoLogin {
            id,
            redirect_uri: Url::parse("https://app.element.io/").unwrap(),
            login_token: "abcdefghijklmnopqrstuvwxyz012345".into(),
            created_at: now,
            state: CompatSsoLoginState::Pending,
        })]
    }
}

impl CompatSsoContext {
    /// Constructs a context for the legacy SSO login page
    #[must_use]
    pub fn new(login: CompatSsoLogin) -> Self
where {
        let action = PostAuthAction::continue_compat_sso_login(login.id);
        Self { login, action }
    }
}

/// Context used by the `emails/verification.{txt,html,subject}` templates
#[derive(Serialize)]
pub struct EmailVerificationContext {
    user: User,
    verification: UserEmailVerification,
}

impl EmailVerificationContext {
    /// Constructs a context for the verification email
    #[must_use]
    pub fn new(user: User, verification: UserEmailVerification) -> Self {
        Self { user, verification }
    }

    /// Get the user to which this email is being sent
    #[must_use]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Get the verification code being sent
    #[must_use]
    pub fn verification(&self) -> &UserEmailVerification {
        &self.verification
    }
}

impl TemplateContext for EmailVerificationContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        User::samples(now, rng)
            .into_iter()
            .map(|user| {
                let email = UserEmail {
                    id: Ulid::from_datetime_with_source(now.into(), rng),
                    user_id: user.id,
                    email: "foobar@example.com".to_owned(),
                    created_at: now,
                    confirmed_at: None,
                };

                let verification = UserEmailVerification {
                    id: Ulid::from_datetime_with_source(now.into(), rng),
                    user_email_id: email.id,
                    code: "123456".to_owned(),
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
    email: UserEmail,
}

impl EmailVerificationPageContext {
    /// Constructs a context for the email verification page
    #[must_use]
    pub fn new(email: UserEmail) -> Self {
        Self {
            form: FormState::default(),
            email,
        }
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<EmailVerificationFormField>) -> Self {
        Self { form, ..self }
    }
}

impl TemplateContext for EmailVerificationPageContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        let email = UserEmail {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            user_id: Ulid::from_datetime_with_source(now.into(), rng),
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
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
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
    linked_user: User,
}

impl UpstreamExistingLinkContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(linked_user: User) -> Self {
        Self { linked_user }
    }
}

impl TemplateContext for UpstreamExistingLinkContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        User::samples(now, rng)
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
    pub fn new(link: &UpstreamOAuthLink) -> Self {
        Self::for_link_id(link.id)
    }

    fn for_link_id(id: Ulid) -> Self {
        let post_logout_action = PostAuthAction::link_upstream(id);
        Self { post_logout_action }
    }
}

impl TemplateContext for UpstreamSuggestLink {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        vec![Self::for_link_id(id)]
    }
}

/// User-editeable fields of the upstream account link form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRegisterFormField {
    /// The username field
    Username,
}

impl FormField for UpstreamRegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username => true,
        }
    }
}

/// Context used by the `pages/upstream_oauth2/do_register.html`
/// templates
#[derive(Serialize, Default)]
pub struct UpstreamRegister {
    imported_localpart: Option<String>,
    force_localpart: bool,
    imported_display_name: Option<String>,
    force_display_name: bool,
    imported_email: Option<String>,
    force_email: bool,
    form_state: FormState<UpstreamRegisterFormField>,
}

impl UpstreamRegister {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the imported localpart
    pub fn set_localpart(&mut self, localpart: String, force: bool) {
        self.imported_localpart = Some(localpart);
        self.force_localpart = force;
    }

    /// Set the imported localpart
    #[must_use]
    pub fn with_localpart(self, localpart: String, force: bool) -> Self {
        Self {
            imported_localpart: Some(localpart),
            force_localpart: force,
            ..self
        }
    }

    /// Set the imported display name
    pub fn set_display_name(&mut self, display_name: String, force: bool) {
        self.imported_display_name = Some(display_name);
        self.force_display_name = force;
    }

    /// Set the imported display name
    #[must_use]
    pub fn with_display_name(self, display_name: String, force: bool) -> Self {
        Self {
            imported_display_name: Some(display_name),
            force_display_name: force,
            ..self
        }
    }

    /// Set the imported email
    pub fn set_email(&mut self, email: String, force: bool) {
        self.imported_email = Some(email);
        self.force_email = force;
    }

    /// Set the imported email
    #[must_use]
    pub fn with_email(self, email: String, force: bool) -> Self {
        Self {
            imported_email: Some(email),
            force_email: force,
            ..self
        }
    }

    /// Set the form state
    pub fn set_form_state(&mut self, form_state: FormState<UpstreamRegisterFormField>) {
        self.form_state = form_state;
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form_state: FormState<UpstreamRegisterFormField>) -> Self {
        Self { form_state, ..self }
    }
}

impl TemplateContext for UpstreamRegister {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![Self::new()]
    }
}

/// Form fields on the device link page
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkFormField {
    /// The device code field
    Code,
}

impl FormField for DeviceLinkFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Code => true,
        }
    }
}

/// Context used by the `device_link.html` template
#[derive(Serialize, Default, Debug)]
pub struct DeviceLinkContext {
    form_state: FormState<DeviceLinkFormField>,
}

impl DeviceLinkContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(mut self, form_state: FormState<DeviceLinkFormField>) -> Self {
        self.form_state = form_state;
        self
    }
}

impl TemplateContext for DeviceLinkContext {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(DeviceLinkFormField::Code, FieldError::Required),
            ),
        ]
    }
}

/// Context used by the `device_consent.html` template
#[derive(Serialize, Debug)]
pub struct DeviceConsentContext {
    grant: DeviceCodeGrant,
    client: Client,
}

impl DeviceConsentContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(grant: DeviceCodeGrant, client: Client) -> Self {
        Self { grant, client }
    }
}

impl TemplateContext for DeviceConsentContext {
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        Client::samples(now, rng)
            .into_iter()
            .map(|client| {
                let grant = DeviceCodeGrant {
                    id: Ulid::from_datetime_with_source(now.into(), rng),
                    state: mas_data_model::DeviceCodeGrantState::Pending,
                    client_id: client.id,
                    scope: [OPENID].into_iter().collect(),
                    user_code: Alphanumeric.sample_string(rng, 6).to_uppercase(),
                    device_code: Alphanumeric.sample_string(rng, 32),
                    created_at: now - Duration::minutes(5),
                    expires_at: now + Duration::minutes(25),
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                    user_agent: Some("Mozilla/5.0".to_owned()),
                };
                Self { grant, client }
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
    fn sample(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        let sample_params = T::sample(now, rng);
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
    lang: Option<String>,
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = &self.code {
            writeln!(f, "code: {code}")?;
        }
        if let Some(description) = &self.description {
            writeln!(f, "{description}")?;
        }

        if let Some(details) = &self.details {
            writeln!(f, "details: {details}")?;
        }

        Ok(())
    }
}

impl TemplateContext for ErrorContext {
    fn sample(_now: chrono::DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
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
    #[must_use]
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Add the language to the context
    #[must_use]
    pub fn with_language(mut self, lang: &DataLocale) -> Self {
        self.lang = Some(lang.to_string());
        self
    }

    /// Get the error code, if any
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    /// Get the description, if any
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the details, if any
    #[must_use]
    pub fn details(&self) -> Option<&str> {
        self.details.as_deref()
    }
}

/// Context used by the not found (`404.html`) template
#[derive(Serialize)]
pub struct NotFoundContext {
    method: String,
    version: String,
    uri: String,
}

impl NotFoundContext {
    /// Constructs a context for the not found page
    #[must_use]
    pub fn new(method: &Method, version: Version, uri: &Uri) -> Self {
        Self {
            method: method.to_string(),
            version: format!("{version:?}"),
            uri: uri.to_string(),
        }
    }
}

impl TemplateContext for NotFoundContext {
    fn sample(_now: DateTime<Utc>, _rng: &mut impl Rng) -> Vec<Self>
    where
        Self: Sized,
    {
        vec![
            Self::new(&Method::GET, Version::HTTP_11, &"/".parse().unwrap()),
            Self::new(&Method::POST, Version::HTTP_2, &"/foo/bar".parse().unwrap()),
            Self::new(
                &Method::PUT,
                Version::HTTP_10,
                &"/foo?bar=baz".parse().unwrap(),
            ),
        ]
    }
}
