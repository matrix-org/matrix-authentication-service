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

use clap::Clap;
use mas_core::templates::Templates;

use super::RootCommand;

#[derive(Clap, Debug)]
pub(super) struct TemplatesCommand {
    #[clap(subcommand)]
    subcommand: TemplatesSubcommand,
}

#[derive(Clap, Debug)]
enum TemplatesSubcommand {
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

impl TemplatesCommand {
    pub async fn run(&self, _root: &RootCommand) -> anyhow::Result<()> {
        use TemplatesSubcommand as SC;
        match &self.subcommand {
            SC::Save { path, overwrite } => {
                Templates::save(path, *overwrite).await?;

                Ok(())
            }

            SC::Check { path, skip_builtin } => {
                let templates = Templates::load(Some(path), !skip_builtin)?;
                templates.check_render()?;

                Ok(())
            }
        }
    }
}
