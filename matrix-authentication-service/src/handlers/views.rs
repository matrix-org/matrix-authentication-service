use tera::Context;
use tide::{Request, Response};

use crate::state::State;

pub async fn index(req: Request<State>) -> tide::Result {
    let state = req.state();
    let content = state.templates().render("index.html", &Context::new())?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}
