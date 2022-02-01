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

use std::path::PathBuf;

use clap::Parser;
use mas_config::TemplatesConfig;
use mas_templates::Templates;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Save the builtin templates to a folder
    Save {
        /// Where the templates should be saved
        path: PathBuf,

        /// Overwrite existing template files
        #[clap(long)]
        overwrite: bool,
    },

    /// Check for template validity at given path.
    Check {
        /// Path where the templates are
        path: String,

        /// Skip loading builtin templates
        #[clap(long)]
        skip_builtin: bool,
    },
}

impl Options {
    pub async fn run(&self, _root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        match &self.subcommand {
            SC::Save { path, overwrite } => {
                Templates::save(path, *overwrite).await?;

                Ok(())
            }

            SC::Check { path, skip_builtin } => {
                let config = TemplatesConfig {
                    path: Some(path.to_string()),
                    builtin: !skip_builtin,
                };
                let templates = Templates::load_from_config(&config).await?;
                templates.check_render().await?;

                Ok(())
            }
        }
    }
}
