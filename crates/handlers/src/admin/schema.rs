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

//! Common schema definitions

use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Metadata, Schema, SchemaObject, StringValidation},
    JsonSchema,
};

/// A type to use for schema definitions of ULIDs
///
/// Use with `#[schemars(with = "crate::admin::schema::Ulid")]`
pub struct Ulid;

impl JsonSchema for Ulid {
    fn schema_name() -> String {
        "ULID".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),

            metadata: Some(Box::new(Metadata {
                title: Some("ULID".into()),
                description: Some("A ULID as per https://github.com/ulid/spec".into()),
                examples: vec![
                    "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                    "01J41912SC8VGAQDD50F6APK91".into(),
                ],
                ..Metadata::default()
            })),

            string: Some(Box::new(StringValidation {
                pattern: Some(r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$".into()),
                ..StringValidation::default()
            })),

            ..SchemaObject::default()
        }
        .into()
    }
}
