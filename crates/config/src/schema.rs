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

//! Useful JSON Schema definitions

use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, NumberValidation, Schema, SchemaObject},
};

/// A network port
pub fn port(_gen: &mut SchemaGenerator) -> Schema {
    Schema::Object(SchemaObject {
        instance_type: Some(InstanceType::Integer.into()),
        number: Some(Box::new(NumberValidation {
            minimum: Some(1.0),
            maximum: Some(65535.0),
            ..NumberValidation::default()
        })),
        ..SchemaObject::default()
    })
}

/// A network hostname
pub fn hostname(_gen: &mut SchemaGenerator) -> Schema {
    Schema::Object(SchemaObject {
        instance_type: Some(InstanceType::String.into()),
        format: Some("hostname".to_string()),
        ..SchemaObject::default()
    })
}
