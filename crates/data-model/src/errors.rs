// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::{collections::HashMap, fmt::Debug, hash::Hash};

use serde::{ser::SerializeMap, Serialize};

pub trait HtmlError: Debug + Send + Sync + 'static {
    fn html_display(&self) -> String;
}

pub trait WrapFormError<FieldType> {
    fn on_form(self) -> ErroredForm<FieldType>;
    fn on_field(self, field: FieldType) -> ErroredForm<FieldType>;
}

impl<E, FieldType> WrapFormError<FieldType> for E
where
    E: HtmlError,
{
    fn on_form(self) -> ErroredForm<FieldType> {
        let mut f = ErroredForm::new();
        f.form.push(FormError {
            error: Box::new(self),
        });
        f
    }

    fn on_field(self, field: FieldType) -> ErroredForm<FieldType> {
        let mut f = ErroredForm::new();
        f.fields.push(FieldError {
            field,
            error: Box::new(self),
        });
        f
    }
}

#[derive(Debug)]
struct FormError {
    error: Box<dyn HtmlError>,
}

impl Serialize for FormError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.error.html_display())
    }
}

#[derive(Debug)]
struct FieldError<FieldType> {
    field: FieldType,
    error: Box<dyn HtmlError>,
}

#[derive(Debug)]
pub struct ErroredForm<FieldType> {
    form: Vec<FormError>,
    fields: Vec<FieldError<FieldType>>,
}

impl<T> Default for ErroredForm<T> {
    fn default() -> Self {
        Self {
            form: Vec::new(),
            fields: Vec::new(),
        }
    }
}

impl<T> ErroredForm<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            form: Vec::new(),
            fields: Vec::new(),
        }
    }
}

impl<FieldType: Copy + Serialize + Hash + Eq> Serialize for ErroredForm<FieldType> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        let has_errors = !self.form.is_empty() || !self.fields.is_empty();
        map.serialize_entry("has_errors", &has_errors)?;
        map.serialize_entry("form_errors", &self.form)?;

        let fields: HashMap<FieldType, Vec<String>> =
            self.fields.iter().fold(HashMap::new(), |mut map, err| {
                map.entry(err.field)
                    .or_default()
                    .push(err.error.html_display());
                map
            });

        map.serialize_entry("fields_errors", &fields)?;

        map.end()
    }
}
