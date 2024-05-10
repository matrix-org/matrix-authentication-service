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
use figment::Figment;
use mas_config::{
    BrandingConfig, CaptchaConfig, ConfigurationSection, ExperimentalConfig, MatrixConfig,
    PasswordsConfig, TemplatesConfig,
};
use mas_storage::{Clock, SystemClock};
use rand::SeedableRng;
use tracing::info_span;

use crate::util::{site_config_from_config, templates_from_config};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check that the templates specified in the config are valid
    Check,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<()> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Check => {
                let _span = info_span!("cli.templates.check").entered();

                let template_config = TemplatesConfig::extract(figment)?;
                let branding_config = BrandingConfig::extract(figment)?;
                let matrix_config = MatrixConfig::extract(figment)?;
                let experimental_config = ExperimentalConfig::extract(figment)?;
                let password_config = PasswordsConfig::extract(figment)?;
                let captcha_config = CaptchaConfig::extract(figment)?;

                let clock = SystemClock::default();
                // XXX: we should disallow SeedableRng::from_entropy
                let mut rng = rand_chacha::ChaChaRng::from_entropy();
                let url_builder =
                    mas_router::UrlBuilder::new("https://example.com/".parse()?, None, None);
                let site_config = site_config_from_config(
                    &branding_config,
                    &matrix_config,
                    &experimental_config,
                    &password_config,
                    &captcha_config,
                )?;
                let templates =
                    templates_from_config(&template_config, &site_config, &url_builder).await?;
                templates.check_render(clock.now(), &mut rng)?;

                Ok(())
            }
        }
    }
}
