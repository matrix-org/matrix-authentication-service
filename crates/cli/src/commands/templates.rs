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

use camino::Utf8PathBuf;
use clap::Parser;
use mas_storage::{Clock, SystemClock};
use mas_templates::Templates;
use rand::SeedableRng;
use tracing::info_span;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check for template validity at given path.
    Check {
        /// Path where the templates are
        path: Utf8PathBuf,
    },
}

impl Options {
    pub async fn run(self, _root: &super::Options) -> anyhow::Result<()> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Check { path } => {
                let _span = info_span!("cli.templates.check").entered();

                let clock = SystemClock::default();
                // XXX: we should disallow SeedableRng::from_entropy
                let mut rng = rand_chacha::ChaChaRng::from_entropy();
                let url_builder = mas_router::UrlBuilder::new("https://example.com/".parse()?);
                let templates = Templates::load(path, url_builder).await?;
                templates.check_render(clock.now(), &mut rng).await?;

                Ok(())
            }
        }
    }
}
