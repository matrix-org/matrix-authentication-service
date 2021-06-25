use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use tide::{sessions::SessionMiddleware, Middleware, Redirect, Server};
use url::Url;

use crate::{
    state::State,
    storage::{ClientLookupError, InvalidRedirectUriError, Storage},
};

mod oauth2;
mod views;

struct BrowserErrorHandler;

#[derive(Debug, Error)]
enum RedirectUriLookupError {
    #[error("Missing client_id")]
    MissingClientId,

    #[error(transparent)]
    ClientLookup(#[from] ClientLookupError),

    #[error("Invalid redirect_uri: {0}")]
    RedirectUriParseError(#[from] url::ParseError),

    #[error(transparent)]
    InvalidRedirectUri(#[from] InvalidRedirectUriError),
}

#[derive(Deserialize)]
struct QueryParams {
    client_id: Option<String>,
    redirect_uri: Option<String>,
}

async fn redirect_uri_from_params(
    params: QueryParams,
    storage: &Storage,
) -> Result<Url, RedirectUriLookupError> {
    use RedirectUriLookupError::*;
    let client_id = params.client_id.ok_or(MissingClientId)?;
    let client = storage.lookup_client(&client_id).await?;
    let redirect_uri: Option<Url> = if let Some(uri) = params.redirect_uri {
        Some(uri.parse()?)
    } else {
        None
    };

    let redirect_uri = client.resolve_redirect_uri(redirect_uri)?;
    Ok(redirect_uri)
}

#[async_trait]
impl Middleware<State> for BrowserErrorHandler {
    async fn handle(
        &self,
        request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        let storage = request.state().storage();
        let params: QueryParams = request.query()?;
        let redirect_uri = redirect_uri_from_params(params, storage).await;
        let mut response = next.run(request).await;
        if let Some(err) = response.take_error() {
            if let Ok(mut redirect_uri) = redirect_uri {
                redirect_uri
                    .query_pairs_mut()
                    .append_pair("error", "server_error")
                    .append_pair("error_description", "unknown server error");

                Ok(Redirect::new(redirect_uri).into())
            } else {
                Ok(format!(
                    "this should be some HTML view displaying the error. {:?}",
                    err
                )
                .into())
            }
        } else {
            Ok(response)
        }
    }
}

pub fn install(app: &mut Server<State>) {
    let state = app.state().clone();

    app.at("/").nest({
        let mut views = tide::with_state(state.clone());
        views.with(state.session_middleware());
        views.with(crate::csrf::HasCsrf);
        views.at("/").get(self::views::index);
        views.at("/login").get(self::views::login);
        views.at("/login").post(self::views::login_post);

        views
            .at("oauth2/authorize")
            .with(BrowserErrorHandler)
            .get(self::oauth2::authorize);

        views
    });

    app.at(".well-known/openid-configuration")
        .get(self::oauth2::discovery);
}
