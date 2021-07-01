use tide::{Request, Response};

use crate::state::State;
use crate::templates::common_context;

pub async fn get(req: Request<State>) -> tide::Result {
    let state = req.state();
    let ctx = common_context(&req).await?;

    let content = state.templates().render("index.html", &ctx)?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}
