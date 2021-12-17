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

use warp::{reject::Reject, Rejection};

#[derive(Debug)]
pub(crate) struct WrappedError(anyhow::Error);

impl warp::reject::Reject for WrappedError {}

pub fn wrapped_error<T: Into<anyhow::Error>>(e: T) -> impl Reject {
    WrappedError(e.into())
}

pub trait WrapError<T> {
    fn wrap_error(self) -> Result<T, Rejection>;
}

impl<T, E> WrapError<T> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn wrap_error(self) -> Result<T, Rejection> {
        self.map_err(|e| warp::reject::custom(WrappedError(e.into())))
    }
}
