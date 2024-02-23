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

use mas_data_model::UserAgent;

/// Simple command-line tool to try out user-agent parsing
///
/// It parses user-agents from stdin and prints the parsed user-agent to stdout.
fn main() {
    for line in std::io::stdin().lines() {
        let user_agent = line.unwrap();
        let user_agent = UserAgent::parse(user_agent);
        println!("{user_agent:?}");
    }
}
