use serde::Deserialize;
use tide::{Redirect, Request, Response};

use crate::csrf::CsrfForm;
use crate::state::State;
use crate::templates::common_context;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

pub async fn get(req: Request<State>) -> tide::Result {
    let state = req.state();
    let ctx = common_context(&req).await?;

    let content = state.templates().render("login.html", &ctx)?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}

pub async fn post(mut req: Request<State>) -> tide::Result {
    let form: CsrfForm<LoginForm> = req.body_form().await?;
    let form = form.verify_csrf(&req)?;
    let state = req.state();

    let user = state
        .storage()
        .login(&form.username, &form.password)
        .await?;

    let session = req.session_mut();
    session.insert("current_user", user.key())?;

    Ok(Redirect::new("/").into())
}
