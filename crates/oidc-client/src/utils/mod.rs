// Copyright 2022 Kévin Commaille.
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

use std::ops::RangeBounds;

use bytes::Buf;
use http::{Response, StatusCode};

use crate::error::ErrorBody;

pub fn http_error_mapper<T>(response: Response<T>) -> Option<ErrorBody>
where
    T: Buf,
{
    let body = response.into_body();
    serde_json::from_reader(body.reader()).ok()
}

pub fn http_all_error_status_codes() -> impl RangeBounds<StatusCode> {
    let Ok(client_errors_start_code) = StatusCode::from_u16(400) else { unreachable!() };
    let Ok(server_errors_end_code) = StatusCode::from_u16(599) else { unreachable!() };

    client_errors_start_code..=server_errors_end_code
}
