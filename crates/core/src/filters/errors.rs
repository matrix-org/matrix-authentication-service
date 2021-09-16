// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::{cmp::Reverse, future::Future, pin::Pin};

use mime::{Mime, STAR};
use serde::Serialize;
use tera::Context;
use tide::{
    http::headers::{ACCEPT, LOCATION},
    Body, Request, StatusCode,
};
use tracing::debug;

use crate::{state::State, templates::common_context};

/// Get the weight parameter for a mime type from 0 to 1000
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn get_weight(mime: &Mime) -> usize {
    let q = mime
        .get_param("q")
        .map_or(1.0_f64, |q| q.as_str().parse().unwrap_or(0.0))
        .min(1.0)
        .max(0.0);

    // Weight have a 3 digit precision so we can multiply by 1000 and cast to
    // int. Sign loss should not happen here because of the min/max up there and
    // truncation does not matter here.
    (q * 1000.0) as _
}

/// Find what content type should be used for a given request
fn preferred_mime_type<'a>(
    request: &Request<State>,
    supported_types: &'a [Mime],
) -> Option<&'a Mime> {
    let accept = request.header(ACCEPT)?;
    // Parse the Accept header as a list of mime types with their associated
    // weight
    let accepted_types: Vec<(Mime, usize)> = {
        let v: Option<Vec<_>> = accept
            .into_iter()
            .flat_map(|value| value.as_str().split(','))
            .map(|mime| {
                mime.trim().parse().ok().map(|mime| {
                    let q = get_weight(&mime);
                    (mime, q)
                })
            })
            .collect();
        let mut v = v?;
        v.sort_by_key(|(_, weight)| Reverse(*weight));
        v
    };

    // For each supported content type, find out if it is accepted with what
    // weight and specificity
    let mut types: Vec<_> = supported_types
        .iter()
        .enumerate()
        .filter_map(|(index, supported)| {
            accepted_types.iter().find_map(|(accepted, weight)| {
                if accepted.type_() == supported.type_()
                    && accepted.subtype() == supported.subtype()
                {
                    // Accept: text/html
                    Some((supported, *weight, 2_usize, index))
                } else if accepted.type_() == supported.type_() && accepted.subtype() == STAR {
                    // Accept: text/*
                    Some((supported, *weight, 1, index))
                } else if accepted.type_() == STAR && accepted.subtype() == STAR {
                    // Accept: */*
                    Some((supported, *weight, 0, index))
                } else {
                    None
                }
            })
        })
        .collect();

    types.sort_by_key(|(_, weight, specificity, index)| {
        (Reverse(*weight), Reverse(*specificity), *index)
    });

    types.first().map(|(mime, _, _, _)| *mime)
}

#[derive(Serialize)]
struct ErrorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl ErrorContext {
    fn should_render(&self) -> bool {
        self.code.is_some() || self.description.is_some() || self.details.is_some()
    }
}

pub fn middleware<'a>(
    request: tide::Request<State>,
    next: tide::Next<'a, State>,
) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
    Box::pin(async {
        let content_type = preferred_mime_type(
            &request,
            &[mime::TEXT_PLAIN, mime::TEXT_HTML, mime::APPLICATION_JSON],
        );
        debug!("Content-Type from Accept: {:?}", content_type);

        // TODO: We should not clone here
        let templates = request.state().templates().clone();

        // TODO: This context should probably be comptuted somewhere else
        let pctx = common_context(&request).await?.clone();

        let mut response = next.run(request).await;

        // Find out what message should be displayed from the response status
        // code
        let (code, description) = match response.status() {
            StatusCode::NotFound => (Some("Not found".to_string()), None),
            StatusCode::MethodNotAllowed => (Some("Method not allowed".to_string()), None),
            StatusCode::Found
            | StatusCode::PermanentRedirect
            | StatusCode::TemporaryRedirect
            | StatusCode::SeeOther => {
                let description = response.header(LOCATION).map(|loc| format!("To {}", loc));
                (Some("Redirecting".to_string()), description)
            }
            StatusCode::InternalServerError => (Some("Internal server error".to_string()), None),
            _ => (None, None),
        };

        // If there is an error associated to the response, format it in a nice
        // way with a backtrace if we have one
        let details = response.take_error().map(|err| {
            format!(
                "{:?}{}",
                err,
                err.backtrace()
                    .map(|bt| format!("\nBacktrace:\n{}", bt.to_string()))
                    .unwrap_or_default()
            )
        });

        let error_context = ErrorContext {
            code,
            description,
            details,
        };

        // This is the case if one of the code, description or details is not
        // None
        if error_context.should_render() {
            match content_type {
                Some(c) if c == &mime::APPLICATION_JSON => {
                    response.set_body(Body::from_json(&error_context)?);
                    response.set_content_type("application/json");
                }
                Some(c) if c == &mime::TEXT_HTML => {
                    let mut ctx = Context::from_serialize(&error_context)?;
                    ctx.extend(pctx);
                    response.set_body(templates.render("error.html", &ctx)?);
                    response.set_content_type("text/html");
                }
                Some(c) if c == &mime::TEXT_PLAIN => {
                    let mut ctx = Context::from_serialize(&error_context)?;
                    ctx.extend(pctx);
                    response.set_body(templates.render("error.txt", &ctx)?);
                    response.set_content_type("text/plain");
                }
                _ => {
                    response.set_body("Unsupported Content-Type in Accept header");
                    response.set_content_type("text/plain");
                    response.set_status(StatusCode::NotAcceptable);
                }
            }
        }

        Ok(response)
    })
}
