use std::convert::TryInto;

use async_trait::async_trait;
use csrf::CsrfProtection;
use data_encoding::BASE64;
use tide::{http::Cookie, Middleware};
use time::Duration;

use crate::state::State;

pub struct HasCsrf;

#[async_trait]
impl Middleware<State> for HasCsrf {
    async fn handle(
        &self,
        mut request: tide::Request<State>,
        next: tide::Next<'_, State>,
    ) -> tide::Result {
        // Generate, inject and save cookie with CSRF
        let state = request.state();
        let protection = state.csrf_protection();
        let previous_token_value = request
            .cookie("csrf")
            .and_then(|cookie| BASE64.decode(cookie.value().as_bytes()).ok())
            .and_then(|decoded| protection.parse_cookie(&decoded).ok())
            .and_then(|parsed| parsed.value().try_into().ok());
        let (token, cookie) =
            protection.generate_token_pair(previous_token_value.as_ref(), 3600)?;

        request.set_ext(token);

        let mut response = next.run(request).await;
        response.insert_cookie(
            Cookie::build("csrf", cookie.b64_string())
                .http_only(true)
                .max_age(Duration::seconds(3600))
                .same_site(tide::http::cookies::SameSite::Strict)
                .finish(),
        );

        Ok(response)
    }
}
