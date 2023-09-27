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

use pad::{Alignment, PadStr};
use serde::Serialize;
use serde_json::{ser::PrettyFormatter, Value};
use thiserror::Error;

use super::{ArgumentList, Message};
use crate::sprintf::message::{ArgumentReference, MessagePart, Placeholder, TypeSpecifier};

macro_rules! format_placeholder {
    ($value:expr, $type:literal, $placeholder:expr) => {
        format_step_plus_sign!($value, $type, $placeholder, "",)
    };
    ($value:expr, $placeholder:expr) => {
        format_placeholder!($value, "", $placeholder)
    };
}

macro_rules! format_step_plus_sign {
    ($value:expr, $type:literal, $placeholder:expr, $modifiers:expr, $($argk:ident = $argv:expr),* $(,)?) => {{
        if $placeholder.plus_sign {
            format_step_zero!(
                $value,
                $type,
                $placeholder,
                concat!($modifiers, "+"),
                $($argk = $argv),*
            )
        } else {
            format_step_zero!(
                $value,
                $type,
                $placeholder,
                $modifiers,
                $($argk = $argv),*
            )
        }
    }};
}

macro_rules! format_step_zero {
    ($value:expr, $type:literal, $placeholder:expr, $modifiers:expr, $($argk:ident = $argv:expr),* $(,)?) => {{
        if $placeholder.padding_specifier_is_zero() {
            format_step_width!(
                $value,
                $type,
                $placeholder,
                concat!($modifiers, "0"),
                $($argk = $argv),*
            )
        } else {
            format_step_width!(
                $value,
                $type,
                $placeholder,
                $modifiers,
                $($argk = $argv),*
            )
        }
    }};
}

macro_rules! format_step_width {
    ($value:expr, $type:literal, $placeholder:expr, $modifiers:expr, $($argk:ident = $argv:expr),* $(,)?) => {{
        if let Some(width) = $placeholder.numeric_width() {
            format_step_precision!(
                $value,
                $type,
                $placeholder,
                concat!($modifiers, "width$"),
                width = width,
                $($argk = $argv),*
            )
        } else {
            format_step_precision!(
                $value,
                $type,
                $placeholder,
                $modifiers,
                $($argk = $argv),*
            )
        }
    }};
}

macro_rules! format_step_precision {
    ($value:expr, $type:literal, $placeholder:expr, $modifiers:expr, $($argk:ident = $argv:expr),* $(,)?) => {{
        if let Some(precision) = $placeholder.precision {
            format_end!(
                $value,
                $type,
                $placeholder,
                concat!($modifiers, ".precision$"),
                precision = precision,
                $($argk = $argv),*
            )
        } else {
            format_end!(
                $value,
                $type,
                $placeholder,
                $modifiers,
                $($argk = $argv),*
            )
        }
    }};
}

macro_rules! format_end {
    ($value:expr, $type:literal, $placeholder:expr, $modifiers:expr, $($argk:ident = $argv:expr),* $(,)?) => {
        format!(concat!("{value:", $modifiers, $type, "}"), value = $value, $($argk = $argv),*)
    };
}

#[derive(Debug)]
pub enum ValueType {
    String,
    Number,
    Float,
    Null,
    Bool,
    Array,
    Object,
}

impl ValueType {
    fn of_value(value: &Value) -> Self {
        match value {
            Value::String(_) => Self::String,
            Value::Number(_) => Self::Number,
            Value::Null => Self::Null,
            Value::Bool(_) => Self::Bool,
            Value::Array(_) => Self::Array,
            Value::Object(_) => Self::Object,
        }
    }
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Can't format a {value_type:?} as a %{type_specifier}")]
    InvalidTypeSpecifier {
        type_specifier: TypeSpecifier,
        value_type: ValueType,
    },

    #[error("Unsupported type specifier %{type_specifier}")]
    UnsupportedTypeSpecifier { type_specifier: TypeSpecifier },

    #[error("Unexpected number type")]
    NumberIsNotANumber,

    #[error("Unknown named argument {name}")]
    UnknownNamedArgument { name: String },

    #[error("Unknown indexed argument {index}")]
    UnknownIndexedArgument { index: usize },

    #[error("Not enough arguments")]
    NotEnoughArguments,

    #[error("Can't serialize value")]
    Serialize(#[from] serde_json::Error),

    #[error("Can't convert value to UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

fn find_value<'a>(
    arguments: &'a ArgumentList,
    requested_argument: Option<&ArgumentReference>,
    current_index: usize,
) -> Result<&'a Value, FormatError> {
    match requested_argument {
        Some(ArgumentReference::Named(name)) => {
            arguments
                .get_by_name(name)
                .ok_or(FormatError::UnknownNamedArgument {
                    name: name.to_owned(),
                })
        }

        Some(ArgumentReference::Indexed(index)) => arguments
            .get_by_index(*index - 1)
            .ok_or(FormatError::UnknownIndexedArgument { index: *index }),

        None => arguments
            .get_by_index(current_index)
            .ok_or(FormatError::NotEnoughArguments),
    }
}

/// An approximation of JS's Number.prototype.toPrecision
fn to_precision(number: f64, mut placeholder: Placeholder) -> String {
    // If the precision is not set, then we just format the number as normal
    let Some(precision) = placeholder.precision else {
        return format_placeholder!(number, &placeholder);
    };

    // This treats NaN, Infinity, -Infinity and zero without any special handling
    if !number.is_normal() {
        return format_placeholder!(number, &placeholder);
    }

    // This tells us how many numbers are before the decimal point
    let log10 = number.abs().log10().floor() as i32;
    // We can fit the number in the precision, so we just format it as normal
    if log10 > 0 && log10 <= precision as i32 || number.abs() < 10.0 {
        // We remove the number of digits before the decimal point from the precision
        placeholder.precision = Some(precision - 1 - log10.max(0) as usize);
        format_placeholder!(number, &placeholder)
    } else {
        // Else in scientific notation there is always one digit before the decimal
        // point
        placeholder.precision = Some(precision - 1);
        format_placeholder!(number, "e", &placeholder)
    }
}

fn format_value(value: &Value, placeholder: &Placeholder) -> Result<String, FormatError> {
    match (value, &placeholder.type_specifier) {
        (Value::Number(number), ts @ TypeSpecifier::BinaryNumber) => {
            if let Some(number) = number.as_u64() {
                Ok(format_placeholder!(number, "b", placeholder))
            } else if let Some(number) = number.as_i64() {
                Ok(format_placeholder!(number, "b", placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: *ts,
                    value_type: ValueType::Float,
                })
            }
        }
        (v, ts @ TypeSpecifier::BinaryNumber) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (Value::String(string), TypeSpecifier::CharacterAsciiValue) if string.len() == 1 => {
            Ok(format_placeholder!(string, placeholder))
        }
        (Value::Number(n), TypeSpecifier::CharacterAsciiValue) => {
            if let Some(character) = n
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .and_then(|n| char::try_from(n).ok())
            {
                Ok(format_placeholder!(character, placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: TypeSpecifier::CharacterAsciiValue,
                    value_type: ValueType::Number,
                })
            }
        }
        (v, ts @ TypeSpecifier::CharacterAsciiValue) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (
            Value::Number(number),
            ts @ (TypeSpecifier::DecimalNumber | TypeSpecifier::IntegerNumber),
        ) => {
            if let Some(number) = number.as_u64() {
                Ok(format_placeholder!(number, placeholder))
            } else if let Some(number) = number.as_i64() {
                Ok(format_placeholder!(number, placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: *ts,
                    value_type: ValueType::Float,
                })
            }
        }
        (v, ts @ (TypeSpecifier::DecimalNumber | TypeSpecifier::IntegerNumber)) => {
            Err(FormatError::InvalidTypeSpecifier {
                type_specifier: *ts,
                value_type: ValueType::of_value(v),
            })
        }

        (Value::Number(number), ts @ TypeSpecifier::UnsignedDecimalNumber) => {
            if let Some(number) = number.as_u64() {
                Ok(format_placeholder!(number, placeholder))
            } else if let Some(number) = number.as_i64() {
                // Truncate to a i32 to mimic JS's behaviour
                let number = number as i32;
                // Then cast to u32 to mimic JS's behaviour
                let number = number as u32;
                Ok(format_placeholder!(number, placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: *ts,
                    value_type: ValueType::Float,
                })
            }
        }
        (v, ts @ TypeSpecifier::UnsignedDecimalNumber) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (Value::Number(number), TypeSpecifier::ScientificNotation) => {
            if let Some(number) = number.as_u64() {
                Ok(format_placeholder!(number, "e", placeholder))
            } else if let Some(number) = number.as_i64() {
                Ok(format_placeholder!(number, "e", placeholder))
            } else if let Some(number) = number.as_f64() {
                Ok(format_placeholder!(number, "e", placeholder))
            } else {
                // This should never happen
                Err(FormatError::NumberIsNotANumber)
            }
        }
        (v, ts @ TypeSpecifier::ScientificNotation) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (Value::Number(number), TypeSpecifier::FloatingPointNumber) => {
            if let Some(number) = number.as_u64() {
                Ok(format_placeholder!(number, placeholder))
            } else if let Some(number) = number.as_i64() {
                Ok(format_placeholder!(number, placeholder))
            } else if let Some(number) = number.as_f64() {
                Ok(format_placeholder!(number, placeholder))
            } else {
                // This should never happen
                Err(FormatError::NumberIsNotANumber)
            }
        }
        (v, ts @ TypeSpecifier::FloatingPointNumber) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (Value::Number(number), TypeSpecifier::FloatingPointNumberWithSignificantDigits) => {
            if let Some(number) = number.as_f64() {
                Ok(to_precision(number, placeholder.clone()))
            } else {
                // This might happen if the integer is too big to be represented as a f64
                Err(FormatError::NumberIsNotANumber)
            }
        }
        (v, ts @ TypeSpecifier::FloatingPointNumberWithSignificantDigits) => {
            Err(FormatError::InvalidTypeSpecifier {
                type_specifier: *ts,
                value_type: ValueType::of_value(v),
            })
        }

        (Value::Number(number), ts @ TypeSpecifier::OctalNumber) => {
            if let Some(number) = number.as_u64() {
                Ok(format_placeholder!(number, "o", placeholder))
            } else if let Some(number) = number.as_i64() {
                // Truncate to a i32 to mimic JS's behaviour
                let number = number as i32;
                // Bit by bit cast to u32 to mimic JS's behaviour
                let number = number as u32;
                Ok(format_placeholder!(number, "o", placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: *ts,
                    value_type: ValueType::Float,
                })
            }
        }
        (v, ts @ TypeSpecifier::OctalNumber) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (Value::String(string), TypeSpecifier::String) => {
            Ok(format_placeholder!(string, placeholder))
        }
        (Value::Number(number), TypeSpecifier::String) => {
            let string = format!("{number}");
            Ok(format_placeholder!(string, placeholder))
        }
        (v, ts @ TypeSpecifier::String) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (Value::Bool(boolean), TypeSpecifier::TrueOrFalse) => {
            Ok(format_placeholder!(boolean, placeholder))
        }
        (v, ts @ TypeSpecifier::TrueOrFalse) => Err(FormatError::InvalidTypeSpecifier {
            type_specifier: *ts,
            value_type: ValueType::of_value(v),
        }),

        (v, TypeSpecifier::TypeOfArgument) => match v {
            Value::String(_) => Ok("string".to_owned()),
            Value::Number(_) => Ok("number".to_owned()),
            Value::Null => Ok("null".to_owned()),
            Value::Bool(_) => Ok("boolean".to_owned()),
            Value::Array(_) => Ok("array".to_owned()),
            Value::Object(_) => Ok("object".to_owned()),
        },

        // Unimplemented
        (_v, TypeSpecifier::PrimitiveValue) => Err(FormatError::UnsupportedTypeSpecifier {
            type_specifier: placeholder.type_specifier,
        }),

        (Value::Number(n), ts @ TypeSpecifier::HexadecimalNumberLowercase) => {
            if let Some(number) = n.as_u64() {
                Ok(format_placeholder!(number, "x", placeholder))
            } else if let Some(number) = n.as_i64() {
                // Truncate to a i32 to mimic JS's behaviour
                let number = number as i32;
                // Then cast to u32 to mimic JS's behaviour
                let number = number as u32;
                Ok(format_placeholder!(number, "x", placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: *ts,
                    value_type: ValueType::Float,
                })
            }
        }
        (v, ts @ TypeSpecifier::HexadecimalNumberLowercase) => {
            Err(FormatError::InvalidTypeSpecifier {
                type_specifier: *ts,
                value_type: ValueType::of_value(v),
            })
        }

        (Value::Number(n), ts @ TypeSpecifier::HexadecimalNumberUppercase) => {
            if let Some(number) = n.as_u64() {
                Ok(format_placeholder!(number, "X", placeholder))
            } else if let Some(number) = n.as_i64() {
                // Truncate to a i32 to mimic JS's behaviour
                let number = number as i32;
                // Then cast to u32 to mimic JS's behaviour
                let number = number as u32;
                Ok(format_placeholder!(number, "X", placeholder))
            } else {
                Err(FormatError::InvalidTypeSpecifier {
                    type_specifier: *ts,
                    value_type: ValueType::Float,
                })
            }
        }
        (v, ts @ TypeSpecifier::HexadecimalNumberUppercase) => {
            Err(FormatError::InvalidTypeSpecifier {
                type_specifier: *ts,
                value_type: ValueType::of_value(v),
            })
        }

        (value, TypeSpecifier::Json) => {
            let mut json = Vec::new();
            if let Some(width) = placeholder.width {
                let indent = b" ".repeat(width);
                let mut serializer = serde_json::Serializer::with_formatter(
                    &mut json,
                    PrettyFormatter::with_indent(indent.as_slice()),
                );
                value.serialize(&mut serializer)?;
            } else {
                let mut serializer = serde_json::Serializer::new(&mut json);
                value.serialize(&mut serializer)?;
            };
            let json = String::from_utf8(json)?;
            Ok(format_placeholder!(json, placeholder))
        }
    }
}

impl Message {
    pub fn format(&self, arguments: &ArgumentList) -> Result<String, FormatError> {
        let mut buffer = String::new();

        // Holds the current index of the placeholder we are formatting, which is used
        // by non-named, non-indexed placeholders
        let mut current_placeholder = 0usize;
        for part in self.parts() {
            match part {
                MessagePart::Percent => {
                    buffer.push('%');
                }
                MessagePart::Text(text) => {
                    buffer.push_str(text);
                }
                MessagePart::Placeholder(placeholder) => {
                    let value = find_value(
                        arguments,
                        placeholder.requested_argument.as_ref(),
                        current_placeholder,
                    )?;

                    let formatted = format_value(value, placeholder)?;

                    // Do the extra padding which std::fmt can't really do
                    let formatted = if let Some(width) = placeholder.width {
                        let spacer = placeholder
                            .padding_specifier
                            .map(|p| p.char())
                            .unwrap_or(' ');

                        let alignment = if placeholder.left_align {
                            Alignment::Left
                        } else {
                            Alignment::Right
                        };

                        formatted.pad(width, spacer, alignment, false)
                    } else {
                        formatted
                    };

                    buffer.push_str(&formatted);

                    current_placeholder += 1;
                }
            }
        }

        Ok(buffer)
    }
}
