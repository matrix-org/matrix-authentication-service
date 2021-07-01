use csrf::CsrfProtection;
use data_encoding::BASE64;
use serde::Deserialize;

use crate::state::State;

/// A CSRF-protected form
#[derive(Deserialize)]
pub struct CsrfForm<T> {
    csrf: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> CsrfForm<T> {
    pub fn verify_csrf(self, request: &tide::Request<State>) -> tide::Result<T> {
        // Verify CSRF from body
        let state = request.state();
        let protection = state.csrf_protection();

        let cookie = request
            .cookie("csrf")
            .ok_or_else(|| anyhow::anyhow!("missing csrf cookie"))?; // TODO: proper error
        let cookie = BASE64.decode(cookie.value().as_bytes())?;
        let cookie = protection.parse_cookie(&cookie)?;

        let token = BASE64.decode(self.csrf.as_bytes())?;
        let token = protection.parse_token(&token)?;

        if protection.verify_token_pair(&token, &cookie) {
            Ok(self.inner)
        } else {
            Err(tide::Error::from_str(400, "failed CSRF validation"))
        }
    }
}
