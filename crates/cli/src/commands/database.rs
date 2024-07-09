// Copyright 2021, 2022 The Matrix.org Foundation C.I.C.
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

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSection, DatabaseConfig};
use mas_storage_pg::MIGRATOR;
use tracing::{info_span, Instrument};

use crate::util::database_connection_from_config;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Run database migrations
    Migrate,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let _span = info_span!("cli.database.migrate").entered();
        let config = DatabaseConfig::extract(figment)?;
        let mut conn = database_connection_from_config(&config).await?;

        // Run pending migrations
        MIGRATOR
            .run(&mut conn)
            .instrument(info_span!("db.migrate"))
            .await
            .context("could not run migrations")?;

        Ok(ExitCode::SUCCESS)
    }
}
