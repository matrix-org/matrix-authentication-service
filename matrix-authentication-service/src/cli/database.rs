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

use anyhow::Context;
use clap::Clap;

use super::RootCommand;
use crate::storage::MIGRATOR;

#[derive(Clap, Debug)]
pub(super) struct DatabaseCommand {
    #[clap(subcommand)]
    subcommand: DatabaseSubcommand,
}

#[derive(Clap, Debug)]
enum DatabaseSubcommand {
    /// Run database migrations
    Migrate,
}

impl DatabaseCommand {
    pub async fn run(&self, root: &RootCommand) -> anyhow::Result<()> {
        let config = root.load_config()?;
        let pool = config.database.connect().await?;

        // Run pending migrations
        MIGRATOR
            .run(&pool)
            .await
            .context("could not run migrations")?;

        Ok(())
    }
}
