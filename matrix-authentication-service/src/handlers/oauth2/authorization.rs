use tide::{Body, Request, Response};

use oauth2_types::requests::AuthorizationRequest;

use crate::state::State;

pub async fn get(req: Request<State>) -> tide::Result {
    let params: AuthorizationRequest = req.query()?;
    let body = Body::from_json(&params)?;
    Ok(Response::builder(200).body(body).build())
}
