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

use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use tide::{
    http::headers::HeaderValue,
    security::{CorsMiddleware, Origin},
    Middleware, Redirect, Server,
};
use tracing::error;
use url::Url;

use crate::{
    state::State,
    storage::{ClientLookupError, InvalidRedirectUriError, Storage},
};

mod health;
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

async fn redirect_uri_from_params<T>(
    params: QueryParams,
    storage: &Storage<T>,
) -> Result<Url, RedirectUriLookupError> {
    use RedirectUriLookupError::MissingClientId;
    let client_id = params.client_id.ok_or(MissingClientId)?;
    let client = storage.lookup_client(&client_id).await?;
    let redirect_uri: Option<Url> = if let Some(uri) = params.redirect_uri {
        Some(uri.parse()?)
    } else {
        None
    };

    let redirect_uri = client.resolve_redirect_uri(&redirect_uri)?;
    Ok(redirect_uri.clone())
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
            error!("{}", err);
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

    app.at("/health").get(self::health::get);

    app.at("/.well-known").nest({
        let cors = CorsMiddleware::new()
            .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
            .allow_origin(Origin::from("*"))
            .allow_credentials(false);

        let metadata_endpoint =
            self::oauth2::discovery::MetadataEndpoint::from_config(&state.config().oauth2);

        let mut wk = tide::new();
        wk.with(cors);
        wk.at("/openid-configuration").get(metadata_endpoint);
        wk
    });

    app.at("/").nest({
        let mut views = tide::with_state(state.clone());
        views.with(state.session_middleware());
        views.with(state.csrf_middleware());
        views.with(crate::middlewares::errors);

        views.at("/").get(self::views::index::get);

        views
            .at("/login")
            .get(self::views::login::get)
            .post(self::views::login::post);

        views
            .at("/reauth")
            .get(self::views::reauth::get)
            .post(self::views::reauth::post);

        views.at("/logout").post(self::views::logout::post);

        views
            .at("oauth2/authorize")
            .with(BrowserErrorHandler)
            .get(self::oauth2::authorization::get);

        views
    });
}
