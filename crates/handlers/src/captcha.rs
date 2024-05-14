// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use std::net::IpAddr;

use axum::BoxError;
use hyper::Request;
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_data_model::{CaptchaConfig, CaptchaService};
use mas_http::HttpServiceExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower::{Service, ServiceExt};

use crate::BoundActivityTracker;

// https://developers.google.com/recaptcha/docs/verify#api_request
const RECAPTCHA_VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

// https://docs.hcaptcha.com/#verify-the-user-response-server-side
const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";

// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
const CF_TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

#[derive(Debug, Error)]
pub enum Error {
    #[error("A CAPTCHA response was expected, but none was provided")]
    MissingCaptchaResponse,

    #[error("A CAPTCHA response was provided, but no CAPTCHA provider is configured")]
    NoCaptchaConfigured,

    #[error("The CAPTCHA response provided is not valid for the configured service")]
    CaptchaResponseMismatch,

    #[error("The CAPTCHA response provided is invalid: {0:?}")]
    InvalidCaptcha(Vec<ErrorCode>),

    #[error("The CAPTCHA provider returned an invalid response")]
    InvalidResponse,

    #[error("The hostname in the CAPTCHA response ({got:?}) does not match the site hostname ({expected:?})")]
    HostnameMismatch { expected: String, got: String },

    #[error("The CAPTCHA provider returned an error")]
    RequestFailed(#[source] BoxError),
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Form {
    g_recaptcha_response: Option<String>,
    h_captcha_response: Option<String>,
    cf_turnstile_response: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerificationRequest<'a> {
    secret: &'a str,
    response: &'a str,
    remoteip: Option<IpAddr>,
}

#[derive(Debug, Deserialize)]
struct VerificationResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<ErrorCode>>,

    challenge_ts: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// The secret parameter is missing.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    MissingInputSecret,

    /// The secret parameter is invalid or malformed.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    InvalidInputSecret,

    /// The response parameter is missing.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    MissingInputResponse,

    /// The response parameter is invalid or malformed.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    InvalidInputResponse,

    /// The widget ID extracted from the parsed site secret key was invalid or
    /// did not exist.
    ///
    /// Used by Cloudflare Turnstile
    InvalidWidgetId,

    /// The secret extracted from the parsed site secret key was invalid.
    ///
    /// Used by Cloudflare Turnstile
    InvalidParsedSecret,

    /// The request is invalid or malformed.
    ///
    /// Used by Cloudflare Turnstile, hCaptcha, reCAPTCHA
    BadRequest,

    /// The remoteip parameter is missing.
    ///
    /// Used by hCaptcha
    MissingRemoteip,

    /// The remoteip parameter is not a valid IP address or blinded value.
    ///
    /// Used by hCaptcha
    InvalidRemoteip,

    /// The response parameter has already been checked, or has another issue.
    ///
    /// Used by hCaptcha
    InvalidOrAlreadySeenResponse,

    /// You have used a testing sitekey but have not used its matching secret.
    ///
    /// Used by hCaptcha
    NotUsingDummyPasscode,

    /// The sitekey is not registered with the provided secret.
    ///
    /// Used by hCaptcha
    SitekeySecretMismatch,

    /// The response is no longer valid: either is too old or has been used
    /// previously.
    ///
    /// Used by Cloudflare Turnstile, reCAPTCHA
    TimeoutOrDisplicate,

    /// An internal error happened while validating the response. The request
    /// can be retried.
    ///
    /// Used by Cloudflare Turnstile
    InternalError,
}

impl Form {
    #[tracing::instrument(
        skip_all,
        name = "captcha.verify",
        fields(captcha.hostname, captcha.challenge_ts, captcha.service),
        err
    )]
    pub async fn verify(
        &self,
        activity_tracker: &BoundActivityTracker,
        http_client_factory: &HttpClientFactory,
        site_hostname: &str,
        config: Option<&CaptchaConfig>,
    ) -> Result<(), Error> {
        let Some(config) = config else {
            if self.g_recaptcha_response.is_some()
                || self.h_captcha_response.is_some()
                || self.cf_turnstile_response.is_some()
            {
                return Err(Error::NoCaptchaConfigured);
            }

            return Ok(());
        };

        let remoteip = activity_tracker.ip();
        let secret = &config.secret_key;

        let span = tracing::Span::current();
        span.record("captcha.service", tracing::field::debug(config.service));

        let request = match (
            config.service,
            &self.g_recaptcha_response,
            &self.h_captcha_response,
            &self.cf_turnstile_response,
        ) {
            (_, None, None, None) => return Err(Error::MissingCaptchaResponse),

            // reCAPTCHA v2
            (CaptchaService::RecaptchaV2, Some(response), None, None) => {
                Request::post(RECAPTCHA_VERIFY_URL)
                    .body(VerificationRequest {
                        secret,
                        response,
                        remoteip,
                    })
                    .unwrap()
            }

            // hCaptcha
            // XXX: this is also allowing g-recaptcha-response, because apparently hCaptcha thought
            // it was a good idea to send both
            (CaptchaService::HCaptcha, _, Some(response), None) => {
                Request::post(HCAPTCHA_VERIFY_URL)
                    .body(VerificationRequest {
                        secret,
                        response,
                        remoteip,
                    })
                    .unwrap()
            }

            // Cloudflare Turnstile
            (CaptchaService::CloudflareTurnstile, None, None, Some(response)) => {
                Request::post(CF_TURNSTILE_VERIFY_URL)
                    .body(VerificationRequest {
                        secret,
                        response,
                        remoteip,
                    })
                    .unwrap()
            }

            _ => return Err(Error::CaptchaResponseMismatch),
        };

        let client = http_client_factory
            .client("captcha")
            .request_bytes_to_body()
            .form_urlencoded_request()
            .response_body_to_bytes()
            .json_response::<VerificationResponse>()
            .map_err(|e| Error::RequestFailed(e.into()));

        let response = client.ready_oneshot().await?.call(request).await?;
        let response = response.into_body();

        if !response.success {
            return Err(Error::InvalidCaptcha(
                response.error_codes.unwrap_or_default(),
            ));
        }

        // If the response is successful, we should have both the hostname and the
        // challenge_ts
        let Some(hostname) = response.hostname else {
            return Err(Error::InvalidResponse);
        };

        let Some(challenge_ts) = response.challenge_ts else {
            return Err(Error::InvalidResponse);
        };

        span.record("captcha.hostname", &hostname);
        span.record("captcha.challenge_ts", &challenge_ts);

        if hostname != site_hostname {
            return Err(Error::HostnameMismatch {
                expected: site_hostname.to_owned(),
                got: hostname,
            });
        }

        Ok(())
    }
}
