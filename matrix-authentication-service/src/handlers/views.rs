use serde::Deserialize;
use tide::http::Method;
use tide::{Redirect, Request, Response};

use crate::state::State;
use crate::templates::common_context;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

pub async fn index(req: Request<State>) -> tide::Result {
    let state = req.state();
    let ctx = common_context(&req).await?;

    let content = state.templates().render("index.html", &ctx)?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}

pub async fn login(req: Request<State>) -> tide::Result {
    let state = req.state();
    let ctx = common_context(&req).await?;

    let content = state.templates().render("login.html", &ctx)?;
    let body = Response::builder(200)
        .body(content)
        .content_type("text/html")
        .into();
    Ok(body)
}

pub async fn login_post(mut req: Request<State>) -> tide::Result {
    let form: LoginForm = req.body_form().await?;
    let state = req.state();

    let user = state
        .storage()
        .login(&form.username, &form.password)
        .await?;

    let session = req.session_mut();
    session.insert("current_user", user.key())?;

    Ok(Redirect::new("/").into())
}
