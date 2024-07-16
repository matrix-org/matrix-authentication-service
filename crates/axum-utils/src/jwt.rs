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

use axum::response::{IntoResponse, Response};
use axum_extra::typed_header::TypedHeader;
use headers::ContentType;
use mas_jose::jwt::Jwt;
use mime::Mime;

pub struct JwtResponse<T>(pub Jwt<'static, T>);

impl<T> IntoResponse for JwtResponse<T> {
    fn into_response(self) -> Response {
        let application_jwt: Mime = "application/jwt".parse().unwrap();
        let content_type = ContentType::from(application_jwt);
        (TypedHeader(content_type), self.0.into_string()).into_response()
    }
}
