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

use std::{collections::HashSet, string::ToString, sync::Arc};

use serde::Serialize;
use tera::{Context, Error as TeraError, Tera};
use thiserror::Error;
use tracing::{debug, info};
use url::Url;
use warp::reject::Reject;

use crate::{filters::CsrfToken, storage::SessionInfo};

#[derive(Clone)]
pub struct Templates(Arc<Tera>);

#[derive(Error, Debug)]
pub enum TemplateLoadingError {
    #[error("could not load and compile some templates")]
    Compile(#[from] TeraError),

    #[error("missing templates {missing:?}")]
    MissingTemplates {
        missing: HashSet<String>,
        loaded: HashSet<String>,
    },
}

impl Templates {
    /// Load the templates and check all needed templates are properly loaded
    pub fn load() -> Result<Self, TemplateLoadingError> {
        let path = format!("{}/templates/**/*.{{html,txt}}", env!("CARGO_MANIFEST_DIR"));
        info!(%path, "Loading templates");
        let tera = Tera::new(&path)?;

        let loaded: HashSet<_> = tera.get_template_names().collect();
        let needed: HashSet<_> = std::array::IntoIter::new(TEMPLATES).collect();
        debug!(?loaded, ?needed, "Templates loaded");
        let missing: HashSet<_> = needed.difference(&loaded).collect();

        if missing.is_empty() {
            Ok(Self(Arc::new(tera)))
        } else {
            let missing = missing.into_iter().map(ToString::to_string).collect();
            let loaded = loaded.into_iter().map(ToString::to_string).collect();
            Err(TemplateLoadingError::MissingTemplates { missing, loaded })
        }
    }
}

#[derive(Error, Debug)]
pub enum TemplateError {
    #[error("could not prepare context for template {template:?}")]
    Context {
        template: &'static str,
        #[source]
        source: TeraError,
    },

    #[error("could not render template {template:?}")]
    Render {
        template: &'static str,
        #[source]
        source: TeraError,
    },
}

impl Reject for TemplateError {}

/// Count the number of tokens. Used to have a fixed-sized array for the
/// templates list.
macro_rules! count {
    () => (0_usize);
    ( $x:tt $($xs:tt)* ) => (1_usize + count!($($xs)*));
}

/// Macro that helps generating helper function that renders a specific template
/// with a strongly-typed context. It also register the template in a static
/// array to help detecting missing templates at startup time.
///
/// The syntax looks almost like a function to confuse syntax highlighter as
/// little as possible.
macro_rules! register_templates {
    {
        $(
            // Match any attribute on the function, such as #[doc], #[allow(dead_code)], etc.
            $( #[ $attr:meta ] )*
            // The function name
            pub fn $name:ident
                // Optional list of generics. Taken from
                // https://newbedev.com/rust-macro-accepting-type-with-generic-parameters
                $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
                // Type of context taken by the template
                ( $param:ty )
            {
                // The name of the template file
                $template:expr
            }
        )*
    } => {
        /// List of registered templates
        static TEMPLATES: [&'static str; count!( $( $template )* )] = [ $( $template ),* ];

        impl Templates {
            $(
                $(#[$attr])?
                pub fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
                    (&self, context: &$param)
                -> Result<String, TemplateError> {
                    let ctx = Context::from_serialize(context)
                        .map_err(|source| TemplateError::Context { template: $template, source })?;

                    self.0.render($template, &ctx)
                        .map_err(|source| TemplateError::Render { template: $template, source })
                }
            )*
        }
    };
}

register_templates! {
    /// Render the login page
    pub fn render_login(WithCsrf<()>) { "login.html" }

    /// Render the registration page
    pub fn render_register(WithCsrf<()>) { "register.html" }

    /// Render the home page
    pub fn render_index(WithCsrf<WithOptionalSession<()>>) { "index.html" }

    /// Render the re-authentication form
    pub fn render_reauth(WithCsrf<WithSession<()>>) { "reauth.html" }

    /// Render the form used by the form_post response mode
    pub fn render_form_post<T: Serialize>(FormPostContext<T>) { "form_post.html" }
}

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

impl<T: Sized> TemplateContext for T {}

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
