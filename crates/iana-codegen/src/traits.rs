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
use async_trait::async_trait;
use convert_case::{Case, Casing};
use reqwest::Client;
use serde::de::DeserializeOwned;

#[derive(Debug, Clone)]
pub struct Section {
    pub key: &'static str,
    pub doc: &'static str,
    pub url: Option<&'static str>,
}

#[must_use]
pub const fn s(key: &'static str, doc: &'static str) -> Section {
    Section {
        key,
        doc,
        url: None,
    }
}

#[derive(Debug)]
pub struct EnumMember {
    pub value: String,
    pub description: Option<String>,
    pub enum_name: String,
}

#[async_trait]
pub trait EnumEntry: DeserializeOwned + Send + Sync {
    const URL: &'static str;
    const SECTIONS: &'static [Section];

    #[must_use]
    fn sections() -> Vec<Section> {
        Self::SECTIONS
            .iter()
            .map(|s| Section {
                url: Some(Self::URL),
                ..*s
            })
            .collect()
    }

    fn key(&self) -> Option<&'static str>;
    fn name(&self) -> &str;
    fn description(&self) -> Option<&str> {
        None
    }
    fn enum_name(&self) -> String {
        // Do the case transformation twice to have "N_A" turned to "Na" instead of "NA"
        self.name()
            .replace('+', "_")
            .to_case(Case::Pascal)
            .to_case(Case::Pascal)
    }

    async fn fetch(client: &Client) -> anyhow::Result<Vec<(&'static str, EnumMember)>> {
        tracing::info!("Fetching CSV");
        let body = client
            .get(Self::URL)
            .send()
            .await
            .context(format!("can't the CSV at {}", Self::URL))?
            .bytes()
            .await
            .context(format!("can't the CSV body at {}", Self::URL))?;

        let parsed: Result<Vec<_>, _> = csv::Reader::from_reader(body.as_ref())
            .into_deserialize()
            .filter_map(|item: Result<Self, _>| {
                item.map(|item| {
                    item.key().map(|key| {
                        (
                            key,
                            EnumMember {
                                value: item.name().to_string(),
                                description: item.description().map(ToString::to_string),
                                enum_name: item.enum_name(),
                            },
                        )
                    })
                })
                .transpose()
            })
            .collect();

        Ok(parsed.context(format!("can't parse the CSV at {}", Self::URL))?)
    }
}
