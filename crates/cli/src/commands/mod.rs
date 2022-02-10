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

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use mas_config::ConfigurationSection;

mod config;
mod database;
mod debug;
mod manage;
mod server;
mod templates;

#[derive(Parser, Debug)]
enum Subcommand {
    /// Configuration-related commands
    Config(self::config::Options),

    /// Manage the database
    Database(self::database::Options),

    /// Runs the web server
    Server(self::server::Options),

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

impl Options {
    pub async fn run(&self) -> anyhow::Result<()> {
        use Subcommand as S;
        match &self.subcommand {
            Some(S::Config(c)) => c.run(self).await,
            Some(S::Database(c)) => c.run(self).await,
            Some(S::Server(c)) => c.run(self).await,
            Some(S::Manage(c)) => c.run(self).await,
            Some(S::Templates(c)) => c.run(self).await,
            Some(S::Debug(c)) => c.run(self).await,
            None => self::server::Options::default().run(self).await,
        }
    }

    pub fn load_config<'de, T: ConfigurationSection<'de>>(&self) -> anyhow::Result<T> {
        T::load_from_files(&self.config).context("could not load configuration")
    }
}
