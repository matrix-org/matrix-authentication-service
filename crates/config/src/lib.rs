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

#![deny(missing_docs, rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]
// derive(JSONSchema) uses &str.to_string()
#![allow(clippy::str_to_string)]

//! Application configuration logic

#[cfg(all(feature = "docker", feature = "dist"))]
compile_error!("Only one of the `docker` and `dist` features can be enabled at once");

pub(crate) mod schema;
mod sections;
pub(crate) mod util;

pub use self::{
    sections::*,
    util::{ConfigurationSection, ConfigurationSectionExt},
};
