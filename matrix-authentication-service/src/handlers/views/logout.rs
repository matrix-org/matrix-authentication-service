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

use tide::{Redirect, Request};

use crate::{csrf::CsrfForm, state::State};

pub async fn post(mut req: Request<State>) -> tide::Result {
    let form: CsrfForm<()> = req.body_form().await?;
    form.verify_csrf(&req)?;

    let session = req.session_mut();
    session.remove("current_session");

    Ok(Redirect::new("/").into())
}
