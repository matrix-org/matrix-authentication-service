use tide::{Redirect, Request};

use crate::{csrf::CsrfForm, state::State};

pub async fn post(mut req: Request<State>) -> tide::Result {
    let form: CsrfForm<()> = req.body_form().await?;
    let _ = form.verify_csrf(&req)?;

    let session = req.session_mut();
    session.remove("current_user");

    Ok(Redirect::new("/").into())
}
