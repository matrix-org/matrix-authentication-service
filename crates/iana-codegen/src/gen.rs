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

use crate::traits::{EnumMember, Section};

fn raw_string(string: &str) -> String {
    if string.contains('"') {
        format!(r##"r#"{string}"#"##)
    } else {
        format!(r#"r"{string}""#)
    }
}

pub fn struct_def(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
    is_exhaustive: bool,
) -> std::fmt::Result {
    write!(
        f,
        r#"/// {}
///
/// Source: <{}>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]"#,
        section.doc,
        section.url.unwrap(),
    )?;

    if !is_exhaustive {
        write!(
            f,
            r#"
#[non_exhaustive]"#
        )?;
    }

    write!(
        f,
        r#"
pub enum {} {{"#,
        section.key,
    )?;
    for member in list {
        writeln!(f)?;
        if let Some(description) = &member.description {
            writeln!(f, "    /// {description}")?;
        } else {
            writeln!(f, "    /// `{}`", member.value)?;
        }
        writeln!(f, "    {},", member.enum_name)?;
    }

    if !is_exhaustive {
        // Add a variant for custom enums
        writeln!(f)?;
        writeln!(f, "    /// An unknown value.")?;
        writeln!(f, "    Unknown(String),")?;
    }

    writeln!(f, "}}")
}

pub fn display_impl(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
    is_exhaustive: bool,
) -> std::fmt::Result {
    write!(
        f,
        r#"impl core::fmt::Display for {} {{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{
        match self {{"#,
        section.key,
    )?;

    for member in list {
        write!(
            f,
            r#"
            Self::{} => write!(f, "{}"),"#,
            member.enum_name, member.value
        )?;
    }

    if !is_exhaustive {
        write!(
            f,
            r#"
            Self::Unknown(value) => write!(f, "{{value}}"),"#
        )?;
    }

    writeln!(
        f,
        r#"
        }}
    }}
}}"#,
    )
}

pub fn from_str_impl(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
    is_exhaustive: bool,
) -> std::fmt::Result {
    let err_ty = if is_exhaustive {
        "crate::ParseError"
    } else {
        "core::convert::Infallible"
    };
    write!(
        f,
        r#"impl core::str::FromStr for {} {{
    type Err = {err_ty};

    fn from_str(s: &str) -> Result<Self, Self::Err> {{
        match s {{"#,
        section.key,
    )?;

    for member in list {
        write!(
            f,
            r#"
            "{}" => Ok(Self::{}),"#,
            member.value, member.enum_name
        )?;
    }

    if is_exhaustive {
        write!(
            f,
            r#"
            _ => Err(crate::ParseError::new()),"#
        )?;
    } else {
        write!(
            f,
            r#"
            value => Ok(Self::Unknown(value.to_owned())),"#,
        )?;
    }

    writeln!(
        f,
        r#"
        }}
    }}
}}"#,
    )
}

pub fn json_schema_impl(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
) -> std::fmt::Result {
    write!(
        f,
        r#"#[cfg(feature = "schemars")]
impl schemars::JsonSchema for {} {{
    fn schema_name() -> String {{
        "{}".to_owned()
    }}

    #[allow(clippy::too_many_lines)]
    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {{
        let enums = vec!["#,
        section.key, section.key,
    )?;

    for member in list {
        write!(
            f,
            r#"
            // ---
            schemars::schema::SchemaObject {{"#,
        )?;

        if let Some(description) = &member.description {
            write!(
                f,
                r#"
                metadata: Some(Box::new(schemars::schema::Metadata {{
                    description: Some(
                        // ---
                        {}.to_owned(),
                    ),
                    ..Default::default()
                }})),"#,
                raw_string(description),
            )?;
        }

        write!(
            f,
            r#"
                const_value: Some("{}".into()),
                ..Default::default()
            }}
            .into(),"#,
            member.value
        )?;
    }

    writeln!(
        f,
        r#"
        ];

        let description = {};
        schemars::schema::SchemaObject {{
            metadata: Some(Box::new(schemars::schema::Metadata {{
                description: Some(description.to_owned()),
                ..Default::default()
            }})),
            subschemas: Some(Box::new(schemars::schema::SubschemaValidation {{
                any_of: Some(enums),
                ..Default::default()
            }})),
            ..Default::default()
        }}
        .into()
    }}
}}"#,
        raw_string(section.doc),
    )
}

pub fn serde_impl(f: &mut std::fmt::Formatter<'_>, section: &Section) -> std::fmt::Result {
    writeln!(
        f,
        r#"#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for {} {{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {{
        let s = String::deserialize(deserializer)?;
        core::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }}
}}

#[cfg(feature = "serde")]
impl serde::Serialize for {} {{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {{
        serializer.serialize_str(&self.to_string())
    }}
}}"#,
        section.key, section.key,
    )
}
