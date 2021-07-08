use tide::{Body, Request, Response};

use oauth2_types::oidc::Metadata;

use crate::state::State;

pub async fn get(req: Request<State>) -> tide::Result {
    let state = req.state();
    let m = Metadata {
        issuer: state.issuer(),
        authorization_endpoint: state.authorization_endpoint(),
        token_endpoint: state.token_endpoint(),
        jwks_uri: state.jwks_uri(),
        registration_endpoint: None,
        scopes_supported: Default::default(),
        response_types_supported: Default::default(),
        response_modes_supported: Default::default(),
        grant_types_supported: Default::default(),
    };

    let body = Body::from_json(&m)?;

    Ok(Response::builder(200).body(body).build())
}
