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

use std::{
    convert::Infallible,
    net::{Ipv4Addr, TcpListener},
    time::Duration,
};

use hyper::{service::service_fn, Request, Response};
use tokio::signal::unix::SignalKind;
use tokio_streams_util::{server::Server, shutdown::ShutdownStream, ConnectionInfo};

async fn handler(req: Request<hyper::Body>) -> Result<Response<String>, Infallible> {
    tracing::info!("Handling request");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let info = req.extensions().get::<ConnectionInfo>().unwrap();
    let body = format!("{info:?}");
    Ok(Response::new(body))
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 3000))?;
    let service = service_fn(handler);
    let server = Server::try_new(listener, service)?;

    tracing::info!("Listening on 127.0.0.1:3000");

    let shutdown = ShutdownStream::default()
        .with_signal(SignalKind::interrupt())?
        .with_signal(SignalKind::terminate())?;
    server.run(shutdown).await;

    Ok(())
}
