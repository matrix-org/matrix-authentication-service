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

use mas_config::PasswordsConfig;
use mas_handlers::passwords::PasswordManager;

pub async fn password_manager_from_config(
    config: &PasswordsConfig,
) -> Result<PasswordManager, anyhow::Error> {
    let schemes = config
        .load()
        .await?
        .into_iter()
        .map(|(version, algorithm, secret)| {
            use mas_handlers::passwords::Hasher;
            let hasher = match algorithm {
                mas_config::PasswordAlgorithm::Pbkdf2 => Hasher::pbkdf2(secret),
                mas_config::PasswordAlgorithm::Bcrypt { cost } => Hasher::bcrypt(cost, secret),
                mas_config::PasswordAlgorithm::Argon2id => Hasher::argon2id(secret),
            };

            (version, hasher)
        });

    PasswordManager::new(schemes)
}
