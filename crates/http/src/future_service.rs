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

//! A copy of [`tower::util::FutureService`] that also maps the future error to
//! help implementing [`Clone`] on the service

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::ready;
use tower::Service;

#[derive(Clone, Debug)]
pub struct FutureService<F, S> {
    state: State<F, S>,
}

impl<F, S> FutureService<F, S> {
    #[must_use]
    pub fn new(future: F) -> Self {
        Self {
            state: State::Future(future),
        }
    }
}

#[derive(Clone, Debug)]
enum State<F, S> {
    Future(F),
    Service(S),
}

impl<F, S, R, FE, E> Service<R> for FutureService<F, S>
where
    F: Future<Output = Result<S, FE>> + Unpin,
    S: Service<R, Error = E>,
    E: From<FE>,
{
    type Response = S::Response;
    type Error = E;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            self.state = match &mut self.state {
                State::Future(fut) => {
                    let fut = Pin::new(fut);
                    let svc = ready!(fut.poll(cx)?);
                    State::Service(svc)
                }
                State::Service(svc) => return svc.poll_ready(cx),
            };
        }
    }

    fn call(&mut self, req: R) -> Self::Future {
        if let State::Service(svc) = &mut self.state {
            svc.call(req)
        } else {
            panic!("FutureService::call was called before FutureService::poll_ready")
        }
    }
}
