// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use serde::Serialize;
use woothee::{parser::Parser, woothee::VALUE_UNKNOWN};

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct UserAgent {
    pub name: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub model: Option<String>,
    pub raw: String,
}

impl std::ops::Deref for UserAgent {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl UserAgent {
    fn parse_custom(user_agent: &str) -> Option<(&str, &str, &str, &str, Option<&str>)> {
        let regex = regex::Regex::new(r"^(?P<name>[^/]+)/(?P<version>[^ ]+) \((?P<segments>.+)\)$")
            .unwrap();

        let captures = regex.captures(&user_agent)?;
        let name = captures.name("name")?.as_str();
        let version = captures.name("version")?.as_str();
        let segments: Vec<&str> = captures
            .name("segments")?
            .as_str()
            .split(';')
            .map(|s| s.trim())
            .collect();

        match segments[..] {
            ["Linux", "U", os, model, ..] | [model, os, ..] => {
                // Most android model have a `/[build version]` suffix we don't care about
                let model = model
                    .split_once("/")
                    .map(|(model, _)| model)
                    .unwrap_or(model);
                // Some android version also have `Build/[build version]` suffix we don't care
                // about
                let model = model.strip_suffix("Build").unwrap_or(model);
                // And let's trim any leftovers
                let model = model.trim();

                let (os, os_version) = if let Some((os, version)) = os.split_once(' ') {
                    (os, Some(version))
                } else {
                    (os, None)
                };

                Some((name, version, model, os, os_version))
            }
            _ => None,
        }
    }

    pub fn parse(user_agent: String) -> Self {
        if !user_agent.contains("Mozilla/") {
            if let Some((name, version, model, os, os_version)) =
                UserAgent::parse_custom(&user_agent)
            {
                return Self {
                    name: Some(name.to_owned()),
                    version: Some(version.to_owned()),
                    os: Some(os.to_owned()),
                    os_version: os_version.map(|s| s.to_owned()),
                    model: Some(model.to_owned()),
                    raw: user_agent,
                };
            }
        }

        let Some(mut result) = Parser::new().parse(&user_agent) else {
            return Self {
                raw: user_agent,
                name: None,
                version: None,
                os: None,
                os_version: None,
                model: None,
            };
        };

        // Special handling for Chrome user-agent reduction cases
        // https://www.chromium.org/updates/ua-reduction/
        match (result.os, &*result.os_version) {
            // Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/533.88 (KHTML, like Gecko)
            // Chrome/109.1.2342.76 Safari/533.88
            ("Windows 10", "NT 10.0") if user_agent.contains("Windows NT 10.0; Win64; x64") => {
                result.os = "Windows";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like
            // Gecko) Chrome/100.0.4896.133 Safari/537.36
            ("Mac OSX", "10.15.7") if user_agent.contains("Macintosh; Intel Mac OS X 10_15_7") => {
                result.os = "macOS";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)
            // Chrome/100.0.0.0 Safari/537.36
            ("Linux", _) if user_agent.contains("X11; Linux x86_64") => {
                result.os = "Linux";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko)
            // Chrome/107.0.0.0 Safari/537.36
            ("ChromeOS", _) if user_agent.contains("X11; CrOS x86_64 14541.0.0") => {
                result.os = "Chrome OS";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko)
            // Chrome/100.0.0.0 Mobile Safari/537.36
            ("Android", "10") if user_agent.contains("Linux; Android 10; K") => {
                result.os = "Android";
                result.os_version = VALUE_UNKNOWN.into();
            }

            _ => {}
        }

        // For some reason, the version on Windows is on the OS field
        // This transforms `Windows 10` into `Windows` and `10`
        if let Some(version) = result.os.strip_prefix("Windows ") {
            result.os = "Windows";
            result.os_version = version.into();
        }

        Self {
            name: (result.name != VALUE_UNKNOWN).then(|| result.name.to_owned()),
            version: (result.version != VALUE_UNKNOWN).then(|| result.version.to_owned()),
            os: (result.os != VALUE_UNKNOWN).then(|| result.os.to_owned()),
            os_version: (result.os_version != VALUE_UNKNOWN)
                .then(|| result.os_version.into_owned()),
            model: None,
            raw: user_agent,
        }
    }
}
