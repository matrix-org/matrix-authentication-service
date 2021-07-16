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

use std::path::PathBuf;

use anyhow::Context;
use clap::Clap;

use self::{config::ConfigCommand, database::DatabaseCommand, server::ServerCommand};
use crate::config::RootConfig;

mod config;
mod database;
mod server;

#[derive(Clap, Debug)]
enum Subcommand {
    /// Configuration-related commands
    Config(ConfigCommand),

    /// Manage the database
    Database(DatabaseCommand),

    /// Runs the web server
    Server(ServerCommand),
}

#[derive(Clap, Debug)]
pub struct RootCommand {
    /// Path to the configuration file
    #[clap(short, long, global = true, default_value = "config.yaml")]
    config: PathBuf,

    #[clap(subcommand)]
    subcommand: Option<Subcommand>,
}

impl RootCommand {
    pub async fn run(&self) -> anyhow::Result<()> {
        use Subcommand as S;
        match &self.subcommand {
            Some(S::Config(c)) => c.run(self).await,
            Some(S::Database(c)) => c.run(self).await,
            Some(S::Server(c)) => c.run(self).await,
            None => ServerCommand::default().run(self).await,
        }
    }

    fn load_config(&self) -> anyhow::Result<RootConfig> {
        RootConfig::load(&self.config).context("Could not load configuration")
    }
}
