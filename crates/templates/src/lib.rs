// Copyright 2021-2022 The Matrix.org Foundation C.I.C.
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
#![deny(
    clippy::all,
    clippy::str_to_string,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

//! Templates rendering

use std::{collections::HashSet, string::ToString, sync::Arc};

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use mas_router::UrlBuilder;
use rand::Rng;
use serde::Serialize;
use tera::{Context, Error as TeraError, Tera};
use thiserror::Error;
use tokio::{sync::RwLock, task::JoinError};
use tracing::{debug, info, warn};

mod context;
mod forms;
mod functions;

#[macro_use]
mod macros;

pub use self::{
    context::{
        AccountContext, AccountEmailsContext, CompatSsoContext, ConsentContext, EmailAddContext,
        EmailVerificationContext, EmailVerificationPageContext, EmptyContext, ErrorContext,
        FormPostContext, IndexContext, LoginContext, LoginFormField, PolicyViolationContext,
        PostAuthContext, PostAuthContextInner, ReauthContext, ReauthFormField, RegisterContext,
        RegisterFormField, TemplateContext, UpstreamExistingLinkContext, UpstreamRegister,
        UpstreamSuggestLink, WithCsrf, WithOptionalSession, WithSession,
    },
    forms::{FieldError, FormError, FormField, FormState, ToFormState},
};

/// Wrapper around [`tera::Tera`] helping rendering the various templates
#[derive(Debug, Clone)]
pub struct Templates {
    tera: Arc<RwLock<Tera>>,
    url_builder: UrlBuilder,
    path: Utf8PathBuf,
}

/// There was an issue while loading the templates
#[derive(Error, Debug)]
pub enum TemplateLoadingError {
    /// I/O error
    #[error(transparent)]
    IO(#[from] std::io::Error),

    /// Some templates failed to compile
    #[error("could not load and compile some templates")]
    Compile(#[from] TeraError),

    /// Could not join blocking task
    #[error("error from async runtime")]
    Runtime(#[from] JoinError),

    /// There are essential templates missing
    #[error("missing templates {missing:?}")]
    MissingTemplates {
        /// List of missing templates
        missing: HashSet<String>,
        /// List of templates that were loaded
        loaded: HashSet<String>,
    },
}

impl Templates {
    /// Directories to watch
    #[must_use]
    pub fn watch_root(&self) -> &Utf8Path {
        &self.path
    }

    /// Load the templates from the given config
    pub async fn load(
        path: Utf8PathBuf,
        url_builder: UrlBuilder,
    ) -> Result<Self, TemplateLoadingError> {
        let tera = Self::load_(&path, url_builder.clone()).await?;
        Ok(Self {
            tera: Arc::new(RwLock::new(tera)),
            path,
            url_builder,
        })
    }

    async fn load_(path: &Utf8Path, url_builder: UrlBuilder) -> Result<Tera, TemplateLoadingError> {
        let path = path.to_owned();

        // This uses blocking I/Os, do that in a blocking task
        let mut tera = tokio::task::spawn_blocking(move || {
            let path = path.canonicalize_utf8()?;
            let path = format!("{path}/**/*.{{html,txt,subject}}");

            info!(%path, "Loading templates from filesystem");
            Tera::new(&path)
        })
        .await??;

        self::functions::register(&mut tera, url_builder);

        let loaded: HashSet<_> = tera.get_template_names().collect();
        let needed: HashSet<_> = TEMPLATES.into_iter().collect();
        debug!(?loaded, ?needed, "Templates loaded");
        let missing: HashSet<_> = needed.difference(&loaded).collect();

        if missing.is_empty() {
            Ok(tera)
        } else {
            let missing = missing.into_iter().map(ToString::to_string).collect();
            let loaded = loaded.into_iter().map(ToString::to_string).collect();
            Err(TemplateLoadingError::MissingTemplates { missing, loaded })
        }
    }

    /// Reload the templates on disk
    pub async fn reload(&self) -> anyhow::Result<()> {
        // Prepare the new Tera instance
        let new_tera = Self::load_(&self.path, self.url_builder.clone()).await?;

        // Swap it
        *self.tera.write().await = new_tera;

        Ok(())
    }
}

/// Failed to render a template
#[derive(Error, Debug)]
pub enum TemplateError {
    /// Failed to prepare the context used by this template
    #[error("could not prepare context for template {template:?}")]
    Context {
        /// The name of the template being rendered
        template: &'static str,

        /// The underlying error
        #[source]
        source: TeraError,
    },

    /// Failed to render the template
    #[error("could not render template {template:?}")]
    Render {
        /// The name of the template being rendered
        template: &'static str,

        /// The underlying error
        #[source]
        source: TeraError,
    },
}

register_templates! {
    /// Render the login page
    pub fn render_login(WithCsrf<LoginContext>) { "pages/login.html" }

    /// Render the registration page
    pub fn render_register(WithCsrf<RegisterContext>) { "pages/register.html" }

    /// Render the client consent page
    pub fn render_consent(WithCsrf<WithSession<ConsentContext>>) { "pages/consent.html" }

    /// Render the policy violation page
    pub fn render_policy_violation(WithCsrf<WithSession<PolicyViolationContext>>) { "pages/policy_violation.html" }

    /// Render the legacy SSO login consent page
    pub fn render_sso_login(WithCsrf<WithSession<CompatSsoContext>>) { "pages/sso.html" }

    /// Render the home page
    pub fn render_index(WithCsrf<WithOptionalSession<IndexContext>>) { "pages/index.html" }

    /// Render the account management page
    pub fn render_account_index(WithCsrf<WithSession<AccountContext>>) { "pages/account/index.html" }

    /// Render the password change page
    pub fn render_account_password(WithCsrf<WithSession<EmptyContext>>) { "pages/account/password.html" }

    /// Render the emails management
    pub fn render_account_emails(WithCsrf<WithSession<AccountEmailsContext>>) { "pages/account/emails/index.html" }

    /// Render the email verification page
    pub fn render_account_verify_email(WithCsrf<WithSession<EmailVerificationPageContext>>) { "pages/account/emails/verify.html" }

    /// Render the email verification page
    pub fn render_account_add_email(WithCsrf<WithSession<EmailAddContext>>) { "pages/account/emails/add.html" }

    /// Render the re-authentication form
    pub fn render_reauth(WithCsrf<WithSession<ReauthContext>>) { "pages/reauth.html" }

    /// Render the form used by the form_post response mode
    pub fn render_form_post<T: Serialize>(FormPostContext<T>) { "form_post.html" }

    /// Render the HTML error page
    pub fn render_error(ErrorContext) { "pages/error.html" }

    /// Render the email verification email (plain text variant)
    pub fn render_email_verification_txt(EmailVerificationContext) { "emails/verification.txt" }

    /// Render the email verification email (HTML text variant)
    pub fn render_email_verification_html(EmailVerificationContext) { "emails/verification.html" }

    /// Render the email verification subject
    pub fn render_email_verification_subject(EmailVerificationContext) { "emails/verification.subject" }

    /// Render the upstream already linked message
    pub fn render_upstream_oauth2_already_linked(WithCsrf<WithSession<EmptyContext>>) { "pages/upstream_oauth2/already_linked.html" }

    /// Render the upstream link mismatch message
    pub fn render_upstream_oauth2_link_mismatch(WithCsrf<WithSession<UpstreamExistingLinkContext>>) { "pages/upstream_oauth2/link_mismatch.html" }

    /// Render the upstream suggest link message
    pub fn render_upstream_oauth2_suggest_link(WithCsrf<WithSession<UpstreamSuggestLink>>) { "pages/upstream_oauth2/suggest_link.html" }

    /// Render the upstream login screen
    pub fn render_upstream_oauth2_do_login(WithCsrf<UpstreamExistingLinkContext>) { "pages/upstream_oauth2/do_login.html" }

    /// Render the upstream register screen
    pub fn render_upstream_oauth2_do_register(WithCsrf<UpstreamRegister>) { "pages/upstream_oauth2/do_register.html" }
}

impl Templates {
    /// Render all templates with the generated samples to check if they render
    /// properly
    pub async fn check_render(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut impl Rng,
    ) -> anyhow::Result<()> {
        check::render_login(self, now, rng).await?;
        check::render_register(self, now, rng).await?;
        check::render_consent(self, now, rng).await?;
        check::render_policy_violation(self, now, rng).await?;
        check::render_sso_login(self, now, rng).await?;
        check::render_index(self, now, rng).await?;
        check::render_account_index(self, now, rng).await?;
        check::render_account_password(self, now, rng).await?;
        check::render_account_emails(self, now, rng).await?;
        check::render_account_add_email(self, now, rng).await?;
        check::render_account_verify_email(self, now, rng).await?;
        check::render_reauth(self, now, rng).await?;
        check::render_form_post::<EmptyContext>(self, now, rng).await?;
        check::render_error(self, now, rng).await?;
        check::render_email_verification_txt(self, now, rng).await?;
        check::render_email_verification_html(self, now, rng).await?;
        check::render_email_verification_subject(self, now, rng).await?;
        check::render_upstream_oauth2_already_linked(self, now, rng).await?;
        check::render_upstream_oauth2_link_mismatch(self, now, rng).await?;
        check::render_upstream_oauth2_suggest_link(self, now, rng).await?;
        check::render_upstream_oauth2_do_login(self, now, rng).await?;
        check::render_upstream_oauth2_do_register(self, now, rng).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_builtin_templates() {
        #[allow(clippy::disallowed_methods)]
        let now = chrono::Utc::now();
        #[allow(clippy::disallowed_methods)]
        let mut rng = rand::thread_rng();

        let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates/");
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap());
        let templates = Templates::load(path, url_builder).await.unwrap();
        templates.check_render(now, &mut rng).await.unwrap();
    }
}
