// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use std::path::{Path, PathBuf};

use mas_policy::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, PasswordInput, RegisterInput,
};
use schemars::{gen::SchemaSettings, JsonSchema};

fn write_schema<T: JsonSchema>(out_dir: Option<&Path>, file: &str) {
    let mut writer: Box<dyn std::io::Write> = match out_dir {
        Some(out_dir) => {
            let path = out_dir.join(file);
            eprintln!("Writing to {path:?}");
            let file = std::fs::File::create(path).expect("Failed to create file");
            Box::new(std::io::BufWriter::new(file))
        }
        None => {
            eprintln!("--- {file} ---");
            Box::new(std::io::stdout())
        }
    };

    let settings = SchemaSettings::draft07().with(|s| {
        s.option_nullable = false;
        s.option_add_null_type = false;
    });
    let generator = settings.into_generator();
    let schema = generator.into_root_schema_for::<T>();
    serde_json::to_writer_pretty(&mut writer, &schema).expect("Failed to serialize schema");
    writer.flush().expect("Failed to flush writer");
}

/// Write the input schemas to the output directory.
/// They are then used in rego files to type check the input.
fn main() {
    let output_root = std::env::var("OUT_DIR").map(PathBuf::from).ok();
    let output_root = output_root.as_deref();

    write_schema::<RegisterInput>(output_root, "register_input.json");
    write_schema::<ClientRegistrationInput>(output_root, "client_registration_input.json");
    write_schema::<AuthorizationGrantInput>(output_root, "authorization_grant_input.json");
    write_schema::<EmailInput>(output_root, "email_input.json");
    write_schema::<PasswordInput>(output_root, "password_input.json");
}
