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

use std::{collections::HashSet, sync::Arc};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use camino::{Utf8Path, Utf8PathBuf};
use mas_i18n::{Translator};
use mas_router::UrlBuilder;
use mas_spa::ViteManifest;
use rand::Rng;
use serde::Serialize;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{debug, info, warn};
use walkdir::DirEntry;

mod context;
mod forms;
mod functions;

#[macro_use]
mod macros;

pub use self::{
    context::{
        AppContext, CompatSsoContext, ConsentContext, EmailAddContext, EmailVerificationContext,
        EmailVerificationPageContext, EmptyContext, ErrorContext, FormPostContext, IndexContext,
        LoginContext, LoginFormField, NotFoundContext, PolicyViolationContext, PostAuthContext,
        PostAuthContextInner, ReauthContext, ReauthFormField, RegisterContext, RegisterFormField,
        TemplateContext, UpstreamExistingLinkContext, UpstreamRegister, UpstreamSuggestLink,
        WithCsrf, WithLanguage, WithOptionalSession, WithSession,
    },
    forms::{FieldError, FormError, FormField, FormState, ToFormState},
};

/// Escape the given string for use in HTML
///
/// It uses the same crate as the one used by the minijinja templates
#[must_use]
pub fn escape_html(input: &str) -> String {
    v_htmlescape::escape(input).to_string()
}

/// Wrapper around [`minijinja::Environment`] helping rendering the various
/// templates
#[derive(Debug, Clone)]
pub struct Templates {
    environment: Arc<ArcSwap<minijinja::Environment<'static>>>,
    translator: Arc<ArcSwap<Translator>>,
    url_builder: UrlBuilder,
    vite_manifest_path: Utf8PathBuf,
    translations_path: Utf8PathBuf,
    path: Utf8PathBuf,
}

/// There was an issue while loading the templates
#[derive(Error, Debug)]
pub enum TemplateLoadingError {
    /// I/O error
    #[error(transparent)]
    IO(#[from] std::io::Error),

    /// Failed to read the assets manifest
    #[error("failed to read the assets manifest")]
    ViteManifestIO(#[source] std::io::Error),

    /// Failed to deserialize the assets manifest
    #[error("invalid assets manifest")]
    ViteManifest(#[from] serde_json::Error),

    /// Failed to load the translations
    #[error("failed to load the translations")]
    Translations(#[from] mas_i18n::LoadError),

    /// Failed to traverse the filesystem
    #[error("failed to traverse the filesystem")]
    WalkDir(#[from] walkdir::Error),

    /// Encountered non-UTF-8 path
    #[error("encountered non-UTF-8 path")]
    NonUtf8Path(#[from] camino::FromPathError),

    /// Encountered non-UTF-8 path
    #[error("encountered non-UTF-8 path")]
    NonUtf8PathBuf(#[from] camino::FromPathBufError),

    /// Encountered invalid path
    #[error("encountered invalid path")]
    InvalidPath(#[from] std::path::StripPrefixError),

    /// Some templates failed to compile
    #[error("could not load and compile some templates")]
    Compile(#[from] minijinja::Error),

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

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|s| s.starts_with('.'))
}

impl Templates {
    /// Load the templates from the given config
    #[tracing::instrument(
        name = "templates.load",
        skip_all,
        fields(%path),
        err,
    )]
    pub async fn load(
        path: Utf8PathBuf,
        url_builder: UrlBuilder,
        vite_manifest_path: Utf8PathBuf,
        translations_path: Utf8PathBuf,
    ) -> Result<Self, TemplateLoadingError> {
        let (translator, environment) = Self::load_(
            &path,
            url_builder.clone(),
            &vite_manifest_path,
            &translations_path,
        )
        .await?;
        Ok(Self {
            environment: Arc::new(ArcSwap::new(environment)),
            translator: Arc::new(ArcSwap::new(translator)),
            path,
            url_builder,
            vite_manifest_path,
            translations_path,
        })
    }

    async fn load_(
        path: &Utf8Path,
        url_builder: UrlBuilder,
        vite_manifest_path: &Utf8Path,
        translations_path: &Utf8Path,
    ) -> Result<(Arc<Translator>, Arc<minijinja::Environment<'static>>), TemplateLoadingError> {
        let path = path.to_owned();
        let span = tracing::Span::current();

        // Read the assets manifest from disk
        let vite_manifest = tokio::fs::read(vite_manifest_path)
            .await
            .map_err(TemplateLoadingError::ViteManifestIO)?;

        // Parse it
        let vite_manifest: ViteManifest =
            serde_json::from_slice(&vite_manifest).map_err(TemplateLoadingError::ViteManifest)?;

        let translations_path = translations_path.to_owned();
        let translator =
            tokio::task::spawn_blocking(move || Translator::load_from_path(&translations_path))
                .await??;
        let translator = Arc::new(translator);

        let (loaded, mut env) = tokio::task::spawn_blocking(move || {
            span.in_scope(move || {
                let mut loaded: HashSet<_> = HashSet::new();
                let mut env = minijinja::Environment::new();
                let root = path.canonicalize_utf8()?;
                info!(%root, "Loading templates from filesystem");
                for entry in walkdir::WalkDir::new(&root)
                    .min_depth(1)
                    .into_iter()
                    .filter_entry(|e| !is_hidden(e))
                {
                    let entry = entry?;
                    if entry.file_type().is_file() {
                        let path = Utf8PathBuf::try_from(entry.into_path())?;
                        let Some(ext) = path.extension() else {
                            continue;
                        };

                        if ext == "html" || ext == "txt" || ext == "subject" {
                            let relative = path.strip_prefix(&root)?;
                            debug!(%relative, "Registering template");
                            let template = std::fs::read_to_string(&path)?;
                            env.add_template_owned(relative.as_str().to_owned(), template)?;
                            loaded.insert(relative.as_str().to_owned());
                        }
                    }
                }

                Ok::<_, TemplateLoadingError>((loaded, env))
            })
        })
        .await??;

        self::functions::register(
            &mut env,
            url_builder,
            vite_manifest,
            Arc::clone(&translator),
        );

        let env = Arc::new(env);

        let needed: HashSet<_> = TEMPLATES.into_iter().map(ToOwned::to_owned).collect();
        debug!(?loaded, ?needed, "Templates loaded");
        let missing: HashSet<_> = needed.difference(&loaded).cloned().collect();

        if missing.is_empty() {
            Ok((translator, env))
        } else {
            Err(TemplateLoadingError::MissingTemplates { missing, loaded })
        }
    }

    /// Reload the templates on disk
    #[tracing::instrument(
        name = "templates.reload",
        skip_all,
        fields(path = %self.path),
        err,
    )]
    pub async fn reload(&self) -> Result<(), TemplateLoadingError> {
        let (translator, environment) = Self::load_(
            &self.path,
            self.url_builder.clone(),
            &self.vite_manifest_path,
            &self.translations_path,
        )
        .await?;

        // Swap them
        self.environment.store(environment);
        self.translator.store(translator);

        Ok(())
    }

    /// Get the translator
    #[must_use]
    pub fn translator(&self) -> Arc<Translator> {
        self.translator.load_full()
    }
}

/// Failed to render a template
#[derive(Error, Debug)]
pub enum TemplateError {
    /// Missing template
    #[error("missing template {template:?}")]
    Missing {
        /// The name of the template being rendered
        template: &'static str,

        /// The underlying error
        #[source]
        source: minijinja::Error,
    },

    /// Failed to render the template
    #[error("could not render template {template:?}")]
    Render {
        /// The name of the template being rendered
        template: &'static str,

        /// The underlying error
        #[source]
        source: minijinja::Error,
    },
}

register_templates! {
    /// Render the not found fallback page
    pub fn render_not_found(WithLanguage<NotFoundContext>) { "pages/404.html" }

    /// Render the frontend app
    pub fn render_app(WithLanguage<AppContext>) { "app.html" }

    /// Render the login page
    pub fn render_login(WithLanguage<WithCsrf<LoginContext>>) { "pages/login.html" }

    /// Render the registration page
    pub fn render_register(WithLanguage<WithCsrf<RegisterContext>>) { "pages/register.html" }

    /// Render the client consent page
    pub fn render_consent(WithLanguage<WithCsrf<WithSession<ConsentContext>>>) { "pages/consent.html" }

    /// Render the policy violation page
    pub fn render_policy_violation(WithLanguage<WithCsrf<WithSession<PolicyViolationContext>>>) { "pages/policy_violation.html" }

    /// Render the legacy SSO login consent page
    pub fn render_sso_login(WithLanguage<WithCsrf<WithSession<CompatSsoContext>>>) { "pages/sso.html" }

    /// Render the home page
    pub fn render_index(WithLanguage<WithCsrf<WithOptionalSession<IndexContext>>>) { "pages/index.html" }

    /// Render the password change page
    pub fn render_account_password(WithLanguage<WithCsrf<WithSession<EmptyContext>>>) { "pages/account/password.html" }

    /// Render the email verification page
    pub fn render_account_verify_email(WithLanguage<WithCsrf<WithSession<EmailVerificationPageContext>>>) { "pages/account/emails/verify.html" }

    /// Render the email verification page
    pub fn render_account_add_email(WithLanguage<WithCsrf<WithSession<EmailAddContext>>>) { "pages/account/emails/add.html" }

    /// Render the re-authentication form
    pub fn render_reauth(WithLanguage<WithCsrf<WithSession<ReauthContext>>>) { "pages/reauth.html" }

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

    /// Render the upstream link mismatch message
    pub fn render_upstream_oauth2_link_mismatch(WithLanguage<WithCsrf<WithSession<UpstreamExistingLinkContext>>>) { "pages/upstream_oauth2/link_mismatch.html" }

    /// Render the upstream suggest link message
    pub fn render_upstream_oauth2_suggest_link(WithLanguage<WithCsrf<WithSession<UpstreamSuggestLink>>>) { "pages/upstream_oauth2/suggest_link.html" }

    /// Render the upstream register screen
    pub fn render_upstream_oauth2_do_register(WithLanguage<WithCsrf<UpstreamRegister>>) { "pages/upstream_oauth2/do_register.html" }
}

impl Templates {
    /// Render all templates with the generated samples to check if they render
    /// properly
    pub fn check_render(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut impl Rng,
    ) -> anyhow::Result<()> {
        check::render_not_found(self, now, rng)?;
        check::render_app(self, now, rng)?;
        check::render_login(self, now, rng)?;
        check::render_register(self, now, rng)?;
        check::render_consent(self, now, rng)?;
        check::render_policy_violation(self, now, rng)?;
        check::render_sso_login(self, now, rng)?;
        check::render_index(self, now, rng)?;
        check::render_account_password(self, now, rng)?;
        check::render_account_add_email(self, now, rng)?;
        check::render_account_verify_email(self, now, rng)?;
        check::render_reauth(self, now, rng)?;
        check::render_form_post::<EmptyContext>(self, now, rng)?;
        check::render_error(self, now, rng)?;
        check::render_email_verification_txt(self, now, rng)?;
        check::render_email_verification_html(self, now, rng)?;
        check::render_email_verification_subject(self, now, rng)?;
        check::render_upstream_oauth2_link_mismatch(self, now, rng)?;
        check::render_upstream_oauth2_suggest_link(self, now, rng)?;
        check::render_upstream_oauth2_do_register(self, now, rng)?;
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
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let vite_manifest_path =
            Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frontend/dist/manifest.json");
        let translations_path =
            Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../../translations");
        let templates = Templates::load(path, url_builder, vite_manifest_path, translations_path)
            .await
            .unwrap();
        templates.check_render(now, &mut rng).unwrap();
    }
}
