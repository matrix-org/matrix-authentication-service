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

use serde::{Deserialize, Serialize};

/// Specifies how to format an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeSpecifier {
    /// `b`
    BinaryNumber,

    /// `c`
    CharacterAsciiValue,

    /// `i`
    DecimalNumber,

    /// `i`
    IntegerNumber,

    /// `e`
    ScientificNotation,

    /// `u`
    UnsignedDecimalNumber,

    /// `f`
    FloatingPointNumber,

    /// `g`
    FloatingPointNumberWithSignificantDigits,

    /// `o`
    OctalNumber,

    /// `s`
    String,

    /// `t`
    TrueOrFalse,

    /// `T`
    TypeOfArgument,

    /// `v`
    PrimitiveValue,

    /// `x`
    HexadecimalNumberLowercase,

    /// `X`
    HexadecimalNumberUppercase,

    /// `j`
    Json,
}

impl TypeSpecifier {
    /// Returns true if the type specifier is a numeric type, which should be
    /// specially formatted with the zero
    const fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::BinaryNumber
                | Self::DecimalNumber
                | Self::IntegerNumber
                | Self::ScientificNotation
                | Self::UnsignedDecimalNumber
                | Self::FloatingPointNumber
                | Self::FloatingPointNumberWithSignificantDigits
                | Self::OctalNumber
                | Self::HexadecimalNumberLowercase
                | Self::HexadecimalNumberUppercase
        )
    }
}

impl std::fmt::Display for TypeSpecifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let specifier = match self {
            Self::BinaryNumber => 'b',
            Self::CharacterAsciiValue => 'c',
            Self::DecimalNumber => 'd',
            Self::IntegerNumber => 'i',
            Self::ScientificNotation => 'e',
            Self::UnsignedDecimalNumber => 'u',
            Self::FloatingPointNumber => 'f',
            Self::FloatingPointNumberWithSignificantDigits => 'g',
            Self::OctalNumber => 'o',
            Self::String => 's',
            Self::TrueOrFalse => 't',
            Self::TypeOfArgument => 'T',
            Self::PrimitiveValue => 'v',
            Self::HexadecimalNumberLowercase => 'x',
            Self::HexadecimalNumberUppercase => 'X',
            Self::Json => 'j',
        };
        write!(f, "{}", specifier)
    }
}

#[derive(Debug, Clone)]
pub enum ArgumentReference {
    Indexed(usize),
    Named(String),
}

impl std::fmt::Display for ArgumentReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgumentReference::Indexed(index) => write!(f, "{}$", index),
            ArgumentReference::Named(name) => write!(f, "({})", name),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PaddingSpecifier {
    Zero,
    Char(char),
}

impl std::fmt::Display for PaddingSpecifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaddingSpecifier::Zero => write!(f, "0"),
            PaddingSpecifier::Char(c) => write!(f, "'{}", c),
        }
    }
}

impl PaddingSpecifier {
    pub fn char(&self) -> char {
        match self {
            PaddingSpecifier::Zero => '0',
            PaddingSpecifier::Char(c) => *c,
        }
    }

    pub const fn is_zero(self) -> bool {
        match self {
            PaddingSpecifier::Zero => true,
            PaddingSpecifier::Char(_) => false,
        }
    }

    pub const fn is_char(self) -> bool {
        match self {
            PaddingSpecifier::Zero => false,
            PaddingSpecifier::Char(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Placeholder {
    pub type_specifier: TypeSpecifier,
    pub requested_argument: Option<ArgumentReference>,
    pub plus_sign: bool,
    pub padding_specifier: Option<PaddingSpecifier>,
    pub left_align: bool,
    pub width: Option<usize>,
    pub precision: Option<usize>,
}

impl Placeholder {
    pub fn padding_specifier_is_zero(&self) -> bool {
        self.padding_specifier
            .map(PaddingSpecifier::is_zero)
            .unwrap_or(false)
    }

    pub fn padding_specifier_is_char(&self) -> bool {
        self.padding_specifier
            .map(PaddingSpecifier::is_char)
            .unwrap_or(false)
    }

    /// Whether it should be formatted as a number for the width argument
    pub fn numeric_width(&self) -> Option<usize> {
        self.width
            .filter(|_| self.padding_specifier_is_zero() && self.type_specifier.is_numeric())
    }
}

impl std::fmt::Display for Placeholder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%")?;
        if let Some(argument) = &self.requested_argument {
            write!(f, "{}", argument)?;
        }

        if self.plus_sign {
            write!(f, "+")?;
        }

        if let Some(padding_specifier) = &self.padding_specifier {
            write!(f, "{}", padding_specifier)?;
        }

        if self.left_align {
            write!(f, "-")?;
        }

        if let Some(width) = self.width {
            write!(f, "{}", width)?;
        }

        if let Some(precision) = self.precision {
            write!(f, ".{}", precision)?;
        }

        write!(f, "{}", self.type_specifier)
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    parts: Vec<MessagePart>,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for part in self.parts.iter() {
            write!(f, "{}", part)?;
        }
        Ok(())
    }
}

impl FromIterator<MessagePart> for Message {
    fn from_iter<T: IntoIterator<Item = MessagePart>>(iter: T) -> Self {
        Self {
            parts: iter.into_iter().collect(),
        }
    }
}

impl IntoIterator for Message {
    type Item = MessagePart;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.parts.into_iter()
    }
}

impl Message {
    pub fn parts(&self) -> std::slice::Iter<'_, MessagePart> {
        self.parts.iter()
    }
}

impl Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let string = self.to_string();
        serializer.serialize_str(&string)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;
        Ok(string.parse().map_err(serde::de::Error::custom)?)
    }
}

#[derive(Debug, Clone)]
pub enum MessagePart {
    Percent,
    Text(String),
    Placeholder(Placeholder),
}

impl From<Placeholder> for MessagePart {
    fn from(placeholder: Placeholder) -> Self {
        Self::Placeholder(placeholder)
    }
}

impl From<String> for MessagePart {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl std::fmt::Display for MessagePart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessagePart::Percent => write!(f, "%%"),
            MessagePart::Text(text) => write!(f, "{}", text),
            MessagePart::Placeholder(placeholder) => write!(f, "{}", placeholder),
        }
    }
}
