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

//! [`tower`] layers and services to help building HTTP client and servers

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::missing_crate_level_docs,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "client")]
mod client;
mod ext;
mod layers;
mod service;

#[cfg(feature = "client")]
pub use self::client::{
    make_traced_client, make_traced_connector, make_untraced_client, ClientInitError, TracedClient,
    TracedConnector, UntracedClient, UntracedConnector,
};
pub use self::{
    ext::{set_propagator, CorsLayerExt, ServiceExt as HttpServiceExt},
    layers::{
        body_to_bytes_response::{self, BodyToBytesResponse, BodyToBytesResponseLayer},
        bytes_to_body_request::{self, BytesToBodyRequest, BytesToBodyRequestLayer},
        catch_http_codes::{self, CatchHttpCodes, CatchHttpCodesLayer},
        client::{ClientLayer, ClientService},
        form_urlencoded_request::{self, FormUrlencodedRequest, FormUrlencodedRequestLayer},
        json_request::{self, JsonRequest, JsonRequestLayer},
        json_response::{self, JsonResponse, JsonResponseLayer},
        otel,
        server::ServerLayer,
    },
    service::{BoxCloneSyncService, HttpService},
};

pub type EmptyBody = http_body::Empty<bytes::Bytes>;
