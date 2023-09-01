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

use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub use crate::traits::*;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "next")]
pub enum PostAuthAction {
    ContinueAuthorizationGrant {
        id: Ulid,
    },
    ContinueCompatSsoLogin {
        id: Ulid,
    },
    ChangePassword,
    LinkUpstream {
        id: Ulid,
    },
    ManageAccount {
        #[serde(flatten)]
        action: Option<AccountAction>,
    },
}

impl PostAuthAction {
    #[must_use]
    pub const fn continue_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueAuthorizationGrant { id }
    }

    #[must_use]
    pub const fn continue_compat_sso_login(id: Ulid) -> Self {
        PostAuthAction::ContinueCompatSsoLogin { id }
    }

    #[must_use]
    pub const fn link_upstream(id: Ulid) -> Self {
        PostAuthAction::LinkUpstream { id }
    }

    pub const fn manage_account(action: Option<AccountAction>) -> Self {
        PostAuthAction::ManageAccount { action }
    }

    pub fn go_next(&self) -> axum::response::Redirect {
        match self {
            Self::ContinueAuthorizationGrant { id } => ContinueAuthorizationGrant(*id).go(),
            Self::ContinueCompatSsoLogin { id } => CompatLoginSsoComplete::new(*id, None).go(),
            Self::ChangePassword => AccountPassword.go(),
            Self::LinkUpstream { id } => UpstreamOAuth2Link::new(*id).go(),
            Self::ManageAccount { action } => Account {
                action: action.clone(),
            }
            .go(),
        }
    }
}

/// `GET /.well-known/openid-configuration`
#[derive(Default, Debug, Clone)]
pub struct OidcConfiguration;

impl SimpleRoute for OidcConfiguration {
    const PATH: &'static str = "/.well-known/openid-configuration";
}

/// `GET /.well-known/webfinger`
#[derive(Default, Debug, Clone)]
pub struct Webfinger;

impl SimpleRoute for Webfinger {
    const PATH: &'static str = "/.well-known/webfinger";
}

/// `GET /.well-known/change-password`
pub struct ChangePasswordDiscovery;

impl SimpleRoute for ChangePasswordDiscovery {
    const PATH: &'static str = "/.well-known/change-password";
}

/// `GET /oauth2/keys.json`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Keys;

impl SimpleRoute for OAuth2Keys {
    const PATH: &'static str = "/oauth2/keys.json";
}

/// `GET /oauth2/userinfo`
#[derive(Default, Debug, Clone)]
pub struct OidcUserinfo;

impl SimpleRoute for OidcUserinfo {
    const PATH: &'static str = "/oauth2/userinfo";
}

/// `POST /oauth2/introspect`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Introspection;

impl SimpleRoute for OAuth2Introspection {
    const PATH: &'static str = "/oauth2/introspect";
}

/// `POST /oauth2/revoke`
#[derive(Default, Debug, Clone)]
pub struct OAuth2Revocation;

impl SimpleRoute for OAuth2Revocation {
    const PATH: &'static str = "/oauth2/revoke";
}

/// `POST /oauth2/token`
#[derive(Default, Debug, Clone)]
pub struct OAuth2TokenEndpoint;

impl SimpleRoute for OAuth2TokenEndpoint {
    const PATH: &'static str = "/oauth2/token";
}

/// `POST /oauth2/registration`
#[derive(Default, Debug, Clone)]
pub struct OAuth2RegistrationEndpoint;

impl SimpleRoute for OAuth2RegistrationEndpoint {
    const PATH: &'static str = "/oauth2/registration";
}

/// `GET /authorize`
#[derive(Default, Debug, Clone)]
pub struct OAuth2AuthorizationEndpoint;

impl SimpleRoute for OAuth2AuthorizationEndpoint {
    const PATH: &'static str = "/authorize";
}

/// `GET /`
#[derive(Default, Debug, Clone)]
pub struct Index;

impl SimpleRoute for Index {
    const PATH: &'static str = "/";
}

/// `GET /health`
#[derive(Default, Debug, Clone)]
pub struct Healthcheck;

impl SimpleRoute for Healthcheck {
    const PATH: &'static str = "/health";
}

/// `GET|POST /login`
#[derive(Default, Debug, Clone)]
pub struct Login {
    post_auth_action: Option<PostAuthAction>,
}

impl Route for Login {
    type Query = PostAuthAction;

    fn route() -> &'static str {
        "/login"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

impl Login {
    #[must_use]
    pub const fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
        }
    }

    #[must_use]
    pub const fn and_continue_grant(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(id)),
        }
    }

    #[must_use]
    pub const fn and_continue_compat_sso_login(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_compat_sso_login(id)),
        }
    }

    #[must_use]
    pub const fn and_link_upstream(id: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::link_upstream(id)),
        }
    }

    /// Get a reference to the login's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self) -> axum::response::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(),
            None => Index.go(),
        }
    }
}

impl From<Option<PostAuthAction>> for Login {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

/// `POST /logout`
#[derive(Default, Debug, Clone)]
pub struct Logout;

impl SimpleRoute for Logout {
    const PATH: &'static str = "/logout";
}

/// `GET|POST /reauth`
#[derive(Default, Debug, Clone)]
pub struct Reauth {
    post_auth_action: Option<PostAuthAction>,
}

impl Reauth {
    #[must_use]
    pub fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
        }
    }

    #[must_use]
    pub fn and_continue_grant(data: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(data)),
        }
    }

    /// Get a reference to the reauth's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self) -> axum::response::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(),
            None => Index.go(),
        }
    }
}

impl Route for Reauth {
    type Query = PostAuthAction;

    fn route() -> &'static str {
        "/reauth"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

impl From<Option<PostAuthAction>> for Reauth {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

/// `GET|POST /register`
#[derive(Default, Debug, Clone)]
pub struct Register {
    post_auth_action: Option<PostAuthAction>,
}

impl Register {
    #[must_use]
    pub fn and_then(action: PostAuthAction) -> Self {
        Self {
            post_auth_action: Some(action),
        }
    }

    #[must_use]
    pub fn and_continue_grant(data: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_grant(data)),
        }
    }

    #[must_use]
    pub fn and_continue_compat_sso_login(data: Ulid) -> Self {
        Self {
            post_auth_action: Some(PostAuthAction::continue_compat_sso_login(data)),
        }
    }

    /// Get a reference to the reauth's post auth action.
    #[must_use]
    pub fn post_auth_action(&self) -> Option<&PostAuthAction> {
        self.post_auth_action.as_ref()
    }

    pub fn go_next(&self) -> axum::response::Redirect {
        match &self.post_auth_action {
            Some(action) => action.go_next(),
            None => Index.go(),
        }
    }
}

impl Route for Register {
    type Query = PostAuthAction;

    fn route() -> &'static str {
        "/register"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

impl From<Option<PostAuthAction>> for Register {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

/// `GET|POST /verify-email/:id`
#[derive(Debug, Clone)]
pub struct AccountVerifyEmail {
    id: Ulid,
    post_auth_action: Option<PostAuthAction>,
}

impl AccountVerifyEmail {
    #[must_use]
    pub fn new(id: Ulid) -> Self {
        Self {
            id,
            post_auth_action: None,
        }
    }

    #[must_use]
    pub fn and_maybe(mut self, action: Option<PostAuthAction>) -> Self {
        self.post_auth_action = action;
        self
    }

    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }
}

impl Route for AccountVerifyEmail {
    type Query = PostAuthAction;
    fn route() -> &'static str {
        "/verify-email/:id"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/verify-email/{}", self.id).into()
    }
}

/// `GET /add-email`
#[derive(Default, Debug, Clone)]
pub struct AccountAddEmail {
    post_auth_action: Option<PostAuthAction>,
}

impl Route for AccountAddEmail {
    type Query = PostAuthAction;
    fn route() -> &'static str {
        "/add-email"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

impl AccountAddEmail {
    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }
}

/// Actions parameters as defined by MSC2965
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum AccountAction {
    Profile,
    SessionsList,
    SessionView { device_id: String },
    SessionEnd { device_id: String },
}

/// `GET /account/`
#[derive(Default, Debug, Clone)]
pub struct Account {
    action: Option<AccountAction>,
}

impl Route for Account {
    type Query = AccountAction;

    fn route() -> &'static str {
        "/account/"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.action.as_ref()
    }
}

/// `GET /account/*`
#[derive(Default, Debug, Clone)]
pub struct AccountWildcard;

impl SimpleRoute for AccountWildcard {
    const PATH: &'static str = "/account/*rest";
}

/// `GET|POST /change-password`
#[derive(Default, Debug, Clone)]
pub struct AccountPassword;

impl SimpleRoute for AccountPassword {
    const PATH: &'static str = "/change-password";
}

/// `GET /authorize/:grant_id`
#[derive(Debug, Clone)]
pub struct ContinueAuthorizationGrant(pub Ulid);

impl Route for ContinueAuthorizationGrant {
    type Query = ();
    fn route() -> &'static str {
        "/authorize/:grant_id"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/authorize/{}", self.0).into()
    }
}

/// `GET /consent/:grant_id`
#[derive(Debug, Clone)]
pub struct Consent(pub Ulid);

impl Route for Consent {
    type Query = ();
    fn route() -> &'static str {
        "/consent/:grant_id"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/consent/{}", self.0).into()
    }
}

/// `GET|POST /_matrix/client/v3/login`
pub struct CompatLogin;

impl SimpleRoute for CompatLogin {
    const PATH: &'static str = "/_matrix/client/:version/login";
}

/// `POST /_matrix/client/v3/logout`
pub struct CompatLogout;

impl SimpleRoute for CompatLogout {
    const PATH: &'static str = "/_matrix/client/:version/logout";
}

/// `POST /_matrix/client/v3/refresh`
pub struct CompatRefresh;

impl SimpleRoute for CompatRefresh {
    const PATH: &'static str = "/_matrix/client/:version/refresh";
}

/// `GET /_matrix/client/v3/login/sso/redirect`
pub struct CompatLoginSsoRedirect;

impl SimpleRoute for CompatLoginSsoRedirect {
    const PATH: &'static str = "/_matrix/client/:version/login/sso/redirect";
}

/// `GET /_matrix/client/v3/login/sso/redirect/`
///
/// This is a workaround for the fact some clients (Element iOS) sends a
/// trailing slash, even though it's not in the spec.
pub struct CompatLoginSsoRedirectSlash;

impl SimpleRoute for CompatLoginSsoRedirectSlash {
    const PATH: &'static str = "/_matrix/client/:version/login/sso/redirect/";
}

/// `GET /_matrix/client/v3/login/sso/redirect/:idp`
pub struct CompatLoginSsoRedirectIdp;

impl SimpleRoute for CompatLoginSsoRedirectIdp {
    const PATH: &'static str = "/_matrix/client/:version/login/sso/redirect/:idp";
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum CompatLoginSsoAction {
    Login,
    Register,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct CompatLoginSsoActionParams {
    #[serde(rename = "org.matrix.msc3824.action")]
    action: CompatLoginSsoAction,
}

/// `GET|POST /complete-compat-sso/:id`
pub struct CompatLoginSsoComplete {
    id: Ulid,
    query: Option<CompatLoginSsoActionParams>,
}

impl CompatLoginSsoComplete {
    #[must_use]
    pub fn new(id: Ulid, action: Option<CompatLoginSsoAction>) -> Self {
        Self {
            id,
            query: action.map(|action| CompatLoginSsoActionParams { action }),
        }
    }
}

impl Route for CompatLoginSsoComplete {
    type Query = CompatLoginSsoActionParams;

    fn query(&self) -> Option<&Self::Query> {
        self.query.as_ref()
    }

    fn route() -> &'static str {
        "/complete-compat-sso/:grant_id"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/complete-compat-sso/{}", self.id).into()
    }
}

/// `GET /upstream/authorize/:id`
pub struct UpstreamOAuth2Authorize {
    id: Ulid,
    post_auth_action: Option<PostAuthAction>,
}

impl UpstreamOAuth2Authorize {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self {
            id,
            post_auth_action: None,
        }
    }

    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }
}

impl Route for UpstreamOAuth2Authorize {
    type Query = PostAuthAction;
    fn route() -> &'static str {
        "/upstream/authorize/:provider_id"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/authorize/{}", self.id).into()
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

/// `GET /upstream/callback/:id`
pub struct UpstreamOAuth2Callback {
    id: Ulid,
}

impl UpstreamOAuth2Callback {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2Callback {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/callback/:provider_id"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/callback/{}", self.id).into()
    }
}

/// `GET /upstream/link/:id`
pub struct UpstreamOAuth2Link {
    id: Ulid,
}

impl UpstreamOAuth2Link {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2Link {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/link/:link_id"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/link/{}", self.id).into()
    }
}

/// `GET /assets`
pub struct StaticAsset {
    path: String,
}

impl StaticAsset {
    #[must_use]
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl Route for StaticAsset {
    type Query = ();
    fn route() -> &'static str {
        "/assets/"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/assets/{}", self.path).into()
    }
}
