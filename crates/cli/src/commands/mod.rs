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

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use mas_config::ConfigurationSection;

mod config;
mod database;
mod debug;
mod manage;
mod server;
mod templates;
mod worker;

#[derive(Parser, Debug)]
enum Subcommand {
    /// Configuration-related commands
    Config(self::config::Options),

    /// Manage the database
    Database(self::database::Options),

    /// Runs the web server
    Server(self::server::Options),

    /// Run the worker
    Worker(self::worker::Options),

    /// Manage the instance
    Manage(self::manage::Options),

    /// Templates-related commands
    Templates(self::templates::Options),

    /// Debug utilities
    Debug(self::debug::Options),
}

#[derive(Parser, Debug)]
pub struct Options {
    /// Path to the configuration file
    #[arg(short, long, global = true, action = clap::ArgAction::Append)]
    config: Vec<Utf8PathBuf>,

    #[command(subcommand)]
    subcommand: Option<Subcommand>,
}

impl Options {
    pub async fn run(mut self) -> anyhow::Result<()> {
        use Subcommand as S;
        match self.subcommand.take() {
            Some(S::Config(c)) => c.run(&self).await,
            Some(S::Database(c)) => c.run(&self).await,
            Some(S::Server(c)) => c.run(&self).await,
            Some(S::Worker(c)) => c.run(&self).await,
            Some(S::Manage(c)) => c.run(&self).await,
            Some(S::Templates(c)) => c.run(&self).await,
            Some(S::Debug(c)) => c.run(&self).await,
            None => self::server::Options::default().run(&self).await,
        }
    }

    pub fn load_config<'de, T: ConfigurationSection<'de>>(&self) -> anyhow::Result<T> {
        let configs = if self.config.is_empty() {
            // Read the MAS_CONFIG environment variable
            std::env::var("MAS_CONFIG")
                // Default to "config.yaml"
                .unwrap_or_else(|_| "config.yaml".to_owned())
                // Split the file list on `:`
                .split(':')
                .map(Utf8PathBuf::from)
                .collect()
        } else {
            self.config.clone()
        };

        T::load_from_files(&configs).context("could not load configuration")
    }
}
