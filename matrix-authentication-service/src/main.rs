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

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::unused_async)]

use anyhow::Context;
use clap::Clap;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

mod cli;
mod config;
mod csrf;
mod errors;
mod filters;
mod handlers;
mod storage;
mod templates;

use self::cli::RootCommand;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup logging & tracing
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);
    subscriber
        .try_init()
        .context("could not initialize logging")?;

    // Parse the CLI arguments
    let opts = RootCommand::parse();

    // And run the command
    opts.run().await
}
