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

use clap::Parser;
use mas_config::{ConfigurationSection, RootConfig};
use rand::SeedableRng;
use tracing::info;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Dump the current config as YAML
    Dump,

    /// Check a config file
    Check,

    /// Generate a new config file
    Generate,
}

impl Options {
    pub async fn run(&self, root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        match &self.subcommand {
            SC::Dump => {
                let config: RootConfig = root.load_config()?;

                serde_yaml::to_writer(std::io::stdout(), &config)?;

                Ok(())
            }
            SC::Check => {
                let _config: RootConfig = root.load_config()?;
                info!(path = ?root.config, "Configuration file looks good");
                Ok(())
            }
            SC::Generate => {
                // XXX: we should disallow SeedableRng::from_entropy
                let rng = rand_chacha::ChaChaRng::from_entropy();
                let config = RootConfig::load_and_generate(rng).await?;

                serde_yaml::to_writer(std::io::stdout(), &config)?;

                Ok(())
            }
        }
    }
}
