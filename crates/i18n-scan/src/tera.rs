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

use mas_i18n::{translations::TranslationTree, Message};
use tera::{
    ast::{Block, Expr, ExprVal, FunctionCall, MacroDefinition, Node},
    Error, Template, Tera,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Message,
    Plural,
}

pub struct Key {
    kind: KeyKind,
    key: String,
}

impl Key {
    fn default_value(&self) -> String {
        match self.kind {
            KeyKind::Message => self.key.clone(),
            KeyKind::Plural => format!("%(count)d {}", self.key),
        }
    }
}

pub fn add_missing(translation_tree: &mut TranslationTree, keys: &[Key]) {
    for translatable in keys {
        let message = Message::from_literal(translatable.default_value());
        let key = translatable
            .key
            .split('.')
            .chain(if translatable.kind == KeyKind::Plural {
                Some("other")
            } else {
                None
            });

        translation_tree.set_if_not_defined(key, message);
    }
}

/// Find all translatable strings in a Tera instance.
///
/// This is not particularly efficient in terms of allocations, but as it is
/// only meant to be used in an utility, it should be fine.
///
/// # Parameters
///
/// * `tera` - The Tera instance to scan.
/// * `function_name` - The name of the translation function. Usually `t`.
///
/// # Errors
///
/// This function will return an error if it encounters an invalid template.
pub fn find_keys(tera: &Tera, function_name: &str) -> Result<Vec<Key>, tera::Error> {
    let names = tera.get_template_names();
    let mut keys = Vec::new();

    for name in names {
        tracing::trace!("Scanning {}", name);
        // This should never fail, but who knows.
        let template = tera.get_template(name)?;
        keys.extend(find_in_template(template, function_name)?);
    }

    Ok(keys)
}

fn find_in_template(template: &Template, function_name: &str) -> Result<Vec<Key>, tera::Error> {
    let mut keys = Vec::new();

    for node in &template.ast {
        keys.extend(find_in_node(node, function_name)?);
    }

    for block in template.blocks.values() {
        keys.extend(find_in_block(block, function_name)?);
    }

    for block_definition in template.blocks_definitions.values() {
        for (_, block) in block_definition {
            keys.extend(find_in_block(block, function_name)?);
        }
    }

    for macro_definition in template.macros.values() {
        keys.extend(find_in_macro_definition(macro_definition, function_name)?);
    }

    Ok(keys)
}

fn find_in_block(block: &Block, function_name: &str) -> Result<Vec<Key>, tera::Error> {
    let mut keys = Vec::new();

    for node in &block.body {
        keys.extend(find_in_node(node, function_name)?);
    }

    Ok(keys)
}

fn find_in_node(node: &Node, function_name: &str) -> Result<Vec<Key>, tera::Error> {
    let mut keys = Vec::new();

    match node {
        Node::VariableBlock(_, expr) => keys.extend(find_in_expr(expr, function_name)?),

        Node::MacroDefinition(_, definition, _) => {
            keys.extend(find_in_macro_definition(definition, function_name)?);
        }

        Node::Set(_, set) => keys.extend(find_in_expr(&set.value, function_name)?),

        Node::FilterSection(_, filter_section, _) => {
            keys.extend(find_in_function_call(
                &filter_section.filter,
                function_name,
            )?);

            for node in &filter_section.body {
                keys.extend(find_in_node(node, function_name)?);
            }
        }

        Node::Block(_, block, _) => keys.extend(find_in_block(block, function_name)?),

        Node::Forloop(_, for_loop, _) => {
            keys.extend(find_in_expr(&for_loop.container, function_name)?);

            for node in &for_loop.body {
                keys.extend(find_in_node(node, function_name)?);
            }

            if let Some(empty_body) = &for_loop.empty_body {
                for node in empty_body {
                    keys.extend(find_in_node(node, function_name)?);
                }
            }
        }
        Node::If(if_block, _) => {
            for (_ws, condition, expr) in &if_block.conditions {
                keys.extend(find_in_expr(condition, function_name)?);

                for node in expr {
                    keys.extend(find_in_node(node, function_name)?);
                }
            }

            if let Some((_ws, expr)) = &if_block.otherwise {
                for node in expr {
                    keys.extend(find_in_node(node, function_name)?);
                }
            }
        }

        Node::Super
        | Node::Text(_)
        | Node::Extends(_, _)
        | Node::Include(_, _, _)
        | Node::ImportMacro(_, _, _)
        | Node::Raw(_, _, _)
        | Node::Break(_)
        | Node::Continue(_)
        | Node::Comment(_, _) => {}
    };

    Ok(keys)
}

fn find_in_macro_definition(
    definition: &MacroDefinition,
    function_name: &str,
) -> Result<Vec<Key>, Error> {
    let mut keys = Vec::new();

    // Walk through argument defaults
    for expr in definition.args.values().flatten() {
        keys.extend(find_in_expr(expr, function_name)?);
    }

    // Walk through the macro body
    for node in &definition.body {
        keys.extend(find_in_node(node, function_name)?);
    }

    Ok(keys)
}

fn find_in_expr_val(expr_val: &ExprVal, function_name: &str) -> Result<Vec<Key>, tera::Error> {
    let mut keys = Vec::new();

    match expr_val {
        ExprVal::String(_)
        | ExprVal::Int(_)
        | ExprVal::Float(_)
        | ExprVal::Bool(_)
        | ExprVal::Ident(_) => {}

        ExprVal::Math(math_expr) => {
            keys.extend(find_in_expr(&math_expr.lhs, function_name)?);
            keys.extend(find_in_expr(&math_expr.rhs, function_name)?);
        }

        ExprVal::Logic(logic_expr) => {
            keys.extend(find_in_expr(&logic_expr.lhs, function_name)?);
            keys.extend(find_in_expr(&logic_expr.rhs, function_name)?);
        }

        ExprVal::Test(test_expr) => {
            for arg in &test_expr.args {
                keys.extend(find_in_expr(arg, function_name)?);
            }
        }

        ExprVal::MacroCall(macro_call) => {
            for arg in macro_call.args.values() {
                keys.extend(find_in_expr(arg, function_name)?);
            }
        }

        ExprVal::FunctionCall(function_call) => {
            keys.extend(find_in_function_call(function_call, function_name)?);
        }

        ExprVal::Array(array) => {
            for expr in array {
                keys.extend(find_in_expr(expr, function_name)?);
            }
        }

        ExprVal::StringConcat(string_concat) => {
            for value in &string_concat.values {
                keys.extend(find_in_expr_val(value, function_name)?);
            }
        }

        ExprVal::In(in_expr) => {
            keys.extend(find_in_expr(&in_expr.lhs, function_name)?);
            keys.extend(find_in_expr(&in_expr.rhs, function_name)?);
        }
    }

    Ok(keys)
}

fn find_in_expr(expr: &Expr, function_name: &str) -> Result<Vec<Key>, tera::Error> {
    let mut keys = Vec::new();

    keys.extend(find_in_expr_val(&expr.val, function_name)?);

    for filter in &expr.filters {
        keys.extend(find_in_function_call(filter, function_name)?);
    }

    Ok(keys)
}

fn find_in_function_call(
    function_call: &FunctionCall,
    function_name: &str,
) -> Result<Vec<Key>, tera::Error> {
    tracing::trace!("Checking function call: {:?}", function_call);
    let mut keys = Vec::new();

    // Regardless of if it is the function we are looking for, we still need to
    // check the arguments
    for expr in function_call.args.values() {
        keys.extend(find_in_expr(expr, function_name)?);
    }

    // If it is the function we are looking for, we need to extract the key
    if function_call.name == function_name {
        let key = function_call
            .args
            .get("key")
            .ok_or(tera::Error::msg("Missing key argument"))?;
        if !key.filters.is_empty() {
            return Err(tera::Error::msg("Key argument must not have filters"));
        }

        if key.negated {
            return Err(tera::Error::msg("Key argument must not be negated"));
        }

        let key = match &key.val {
            tera::ast::ExprVal::String(s) => s.clone(),
            _ => return Err(tera::Error::msg("Key argument must be a string")),
        };

        let kind = if function_call.args.contains_key("count") {
            KeyKind::Plural
        } else {
            KeyKind::Message
        };

        keys.push(Key { kind, key });
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use tera::Tera;

    use super::*;

    #[test]
    fn test_find_keys() {
        let mut tera = Tera::default();
        tera.add_raw_templates([
            ("hello.txt", r#"Hello {{ t(key="world") }}"#),
            ("existing.txt", r#"{{ t(key="hello") }}"#),
            ("plural.txt", r#"{{ t(key="plural", count=4) }}"#),
            // Kitchen sink to make sure we're going through the whole AST
            (
                "macros.txt",
                r#"
                    {% macro test(arg="foo") %}
                        {% if function() == foo is test(t(key="nested.1")) %}
                            {% set foo = t(key="nested.2", arg=5 + 2) ~ "foo" in test %}
                            {{ foo | bar }}
                        {% else %}
                                {% for i in [t(key="nested.3", extra=t(key="nested.4")), "foo"] %}
                                    {{ i | foo }}
                                {% else %}
                                    {{ t(key="nested.5") }}
                                {% endfor %}
                        {% endif %}
                    {% endmacro %}
                "#,
            ),
            (
                "nested.txt",
                r#"
                    {% import "macros.txt" as macros %}
                    {% block test %}
                        {% filter upper %}
                            {{ macros::test(arg=t(key="nested.6")) }}
                        {% endfilter %}
                    {% endblock test %}
                "#,
            ),
        ])
        .unwrap();

        let mut tree = serde_json::from_value(serde_json::json!({
            "hello": "Hello!",
        }))
        .unwrap();

        let keys = find_keys(&tera, "t").unwrap();
        add_missing(&mut tree, &keys);
        let tree = serde_json::to_value(&tree).unwrap();
        assert_eq!(
            tree,
            serde_json::json!({
                "hello": "Hello!",
                "world": "world",
                "plural": {
                    "other": "%(count)d plural"
                },
                "nested": {
                    "1": "nested.1",
                    "2": "nested.2",
                    "3": "nested.3",
                    "4": "nested.4",
                    "5": "nested.5",
                    "6": "nested.6",
                },
            })
        );
    }

    #[test]
    fn test_invalid_key_not_string() {
        let mut tera = Tera::default();
        // This is invalid because the key is not a string
        tera.add_raw_template("invalid.txt", r#"{{ t(key=5) }}"#)
            .unwrap();

        let keys = find_keys(&tera, "t");
        assert!(keys.is_err());
    }

    #[test]
    fn test_invalid_key_filtered() {
        let mut tera = Tera::default();
        // This is invalid because the key argument has a filter
        tera.add_raw_template("invalid.txt", r#"{{ t(key="foo" | bar) }}"#)
            .unwrap();

        let keys = find_keys(&tera, "t");
        assert!(keys.is_err());
    }

    #[test]
    fn test_invalid_key_missing() {
        let mut tera = Tera::default();
        // This is invalid because the key argument is missing
        tera.add_raw_template("invalid.txt", r#"{{ t() }}"#)
            .unwrap();

        let keys = find_keys(&tera, "t");
        assert!(keys.is_err());
    }

    #[test]
    fn test_invalid_key_negated() {
        let mut tera = Tera::default();
        // This is invalid because the key argument is missing
        tera.add_raw_template("invalid.txt", r#"{{ t(key=not "foo") }}"#)
            .unwrap();

        let keys = find_keys(&tera, "t");
        assert!(keys.is_err());
    }
}
