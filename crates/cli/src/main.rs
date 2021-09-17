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
#![allow(clippy::suspicious_else_formatting)]

use std::path::PathBuf;

use anyhow::Context;
use clap::Clap;
use mas_config::ConfigurationSection;
use tracing::trace;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

use self::{
    config::ConfigCommand, database::DatabaseCommand, manage::ManageCommand, server::ServerCommand,
    templates::TemplatesCommand,
};

mod config;
mod database;
mod manage;
mod server;
mod templates;

#[derive(Clap, Debug)]
enum Subcommand {
    /// Configuration-related commands
    Config(ConfigCommand),

    /// Manage the database
    Database(DatabaseCommand),

    /// Runs the web server
    Server(ServerCommand),

    /// Manage the instance
    Manage(ManageCommand),

    /// Templates-related commands
    Templates(TemplatesCommand),
}

#[derive(Clap, Debug)]
struct RootCommand {
    /// Path to the configuration file
    #[clap(
        short,
        long,
        global = true,
        default_value = "config.yaml",
        multiple_occurrences(true)
    )]
    config: Vec<PathBuf>,

    #[clap(subcommand)]
    subcommand: Option<Subcommand>,
}

impl RootCommand {
    async fn run(&self) -> anyhow::Result<()> {
        use Subcommand as S;
        match &self.subcommand {
            Some(S::Config(c)) => c.run(self).await,
            Some(S::Database(c)) => c.run(self).await,
            Some(S::Server(c)) => c.run(self).await,
            Some(S::Manage(c)) => c.run(self).await,
            Some(S::Templates(c)) => c.run(self).await,
            None => ServerCommand::default().run(self).await,
        }
    }

    fn load_config<'de, T: ConfigurationSection<'de>>(&self) -> anyhow::Result<T> {
        T::load_from_files(&self.config).context("could not load configuration")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env files
    if let Err(e) = dotenv::dotenv() {
        // Display the error if it is something other than the .env file not existing
        if !e.not_found() {
            return Err(e).context("could not load .env file");
        }
    }

    // Setup logging & tracing
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);
    subscriber
        .try_init()
        .context("could not initialize logging")?;

    // Parse the CLI arguments
    let opts = RootCommand::parse();

    // And run the command
    trace!(?opts, "Running command");
    opts.run().await
}
