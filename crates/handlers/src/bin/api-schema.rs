// Copyright 2022 The Matrix.org Foundation C.I.C.
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

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::broken_intra_doc_links,
    clippy::future_not_send
)]
#![warn(clippy::pedantic)]

use std::io::Write;

/// This is a dummy state, it should never be used.
///
/// We use it to generate the API schema, which doesn't execute any request.
#[derive(Clone)]
struct DummyState;

macro_rules! impl_from_request_parts {
    ($type:ty) => {
        #[axum::async_trait]
        impl axum::extract::FromRequestParts<DummyState> for $type {
            type Rejection = std::convert::Infallible;

            async fn from_request_parts(
                _parts: &mut axum::http::request::Parts,
                _state: &DummyState,
            ) -> Result<Self, Self::Rejection> {
                unimplemented!("This is a dummy state, it should never be used")
            }
        }
    };
}

macro_rules! impl_from_ref {
    ($type:ty) => {
        impl axum::extract::FromRef<DummyState> for $type {
            fn from_ref(_input: &DummyState) -> Self {
                unimplemented!("This is a dummy state, it should never be used")
            }
        }
    };
}

impl_from_request_parts!(mas_storage::BoxRepository);
impl_from_request_parts!(mas_storage::BoxClock);
impl_from_request_parts!(mas_handlers::BoundActivityTracker);
impl_from_ref!(mas_keystore::Keystore);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (api, _) = mas_handlers::admin_api_router::<DummyState>();
    let mut stdout = std::io::stdout();
    serde_json::to_writer_pretty(&mut stdout, &api)?;

    // Make sure we end with a newline
    stdout.write_all(b"\n")?;

    Ok(())
}
