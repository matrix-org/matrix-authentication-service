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

pub use minijinja::machinery::parse;
use minijinja::{
    machinery::ast::{Call, Const, Expr, Stmt},
    ErrorKind,
};

use crate::key::{Key, KeyKind};

pub fn find_in_stmt<'a>(stmt: &'a Stmt<'a>) -> Result<Vec<Key>, minijinja::Error> {
    let mut keys = Vec::new();

    match stmt {
        Stmt::Template(template) => keys.extend(find_in_stmts(&template.children)?),
        Stmt::EmitExpr(emit_expr) => keys.extend(find_in_expr(&emit_expr.expr)?),
        Stmt::EmitRaw(_raw) => {}
        Stmt::ForLoop(for_loop) => {
            keys.extend(find_in_expr(&for_loop.iter)?);
            keys.extend(find_in_optional_expr(&for_loop.filter_expr)?);
            keys.extend(find_in_expr(&for_loop.target)?);
            keys.extend(find_in_stmts(&for_loop.body)?);
            keys.extend(find_in_stmts(&for_loop.else_body)?);
        }
        Stmt::IfCond(if_cond) => {
            keys.extend(find_in_expr(&if_cond.expr)?);
            keys.extend(find_in_stmts(&if_cond.true_body)?);
            keys.extend(find_in_stmts(&if_cond.false_body)?);
        }
        Stmt::WithBlock(with_block) => {
            keys.extend(find_in_stmts(&with_block.body)?);
            for (left, right) in &with_block.assignments {
                keys.extend(find_in_expr(left)?);
                keys.extend(find_in_expr(right)?);
            }
        }
        Stmt::Set(set) => {
            keys.extend(find_in_expr(&set.target)?);
            keys.extend(find_in_expr(&set.expr)?);
        }
        Stmt::SetBlock(set_block) => {
            keys.extend(find_in_expr(&set_block.target)?);
            keys.extend(find_in_stmts(&set_block.body)?);
            if let Some(expr) = &set_block.filter {
                keys.extend(find_in_expr(expr)?);
            }
        }
        Stmt::AutoEscape(auto_escape) => {
            keys.extend(find_in_expr(&auto_escape.enabled)?);
            keys.extend(find_in_stmts(&auto_escape.body)?);
        }
        Stmt::FilterBlock(filter_block) => {
            keys.extend(find_in_expr(&filter_block.filter)?);
            keys.extend(find_in_stmts(&filter_block.body)?);
        }
        Stmt::Block(block) => {
            keys.extend(find_in_stmts(&block.body)?);
        }
        Stmt::Import(import) => {
            keys.extend(find_in_expr(&import.name)?);
            keys.extend(find_in_expr(&import.expr)?);
        }
        Stmt::FromImport(from_import) => {
            keys.extend(find_in_expr(&from_import.expr)?);
            for (name, alias) in &from_import.names {
                keys.extend(find_in_expr(name)?);
                keys.extend(find_in_optional_expr(alias)?);
            }
        }
        Stmt::Extends(extends) => {
            keys.extend(find_in_expr(&extends.name)?);
        }
        Stmt::Include(include) => {
            keys.extend(find_in_expr(&include.name)?);
        }
        Stmt::Macro(macro_) => {
            keys.extend(find_in_stmts(&macro_.body)?);
            keys.extend(find_in_exprs(&macro_.args)?);
            keys.extend(find_in_exprs(&macro_.defaults)?);
        }
        Stmt::CallBlock(call_block) => {
            keys.extend(find_in_call(&call_block.call)?);
            // TODO: call_block.macro_decl
        }
        Stmt::Do(do_) => {
            keys.extend(find_in_call(&do_.call)?);
        }
    }

    Ok(keys)
}

fn as_const<'a>(expr: &'a Expr<'a>) -> Option<&'a Const> {
    match expr {
        Expr::Const(const_) => Some(const_),
        _ => None,
    }
}

fn find_in_call<'a>(call: &'a Call<'a>) -> Result<Vec<Key>, minijinja::Error> {
    let mut keys = Vec::new();

    if let Expr::Var(var_) = &call.expr {
        // TODO: pass the function name
        if var_.id == "t" {
            // TODO: don't unwrap
            let key = call
                .args
                .get(0)
                .and_then(as_const)
                .and_then(|const_| const_.value.as_str())
                .ok_or(minijinja::Error::new(
                    ErrorKind::UndefinedError,
                    "t() first argument must be a string literal",
                ))?;

            let has_count = call.args.iter().any(|arg| {
                if let Expr::Kwargs(kwargs) = arg {
                    kwargs.pairs.iter().any(|(key, _value)| *key == "count")
                } else {
                    false
                }
            });

            // TODO: detect plurals
            keys.push(Key::new(
                if has_count {
                    KeyKind::Plural
                } else {
                    KeyKind::Message
                },
                key.to_owned(),
            ));
        }
    }

    keys.extend(find_in_expr(&call.expr)?);
    for arg in &call.args {
        keys.extend(find_in_expr(arg)?);
    }

    Ok(keys)
}

fn find_in_stmts<'a>(stmts: &'a [Stmt<'a>]) -> Result<Vec<Key>, minijinja::Error> {
    let mut keys = Vec::new();

    for stmt in stmts {
        keys.extend(find_in_stmt(stmt)?);
    }

    Ok(keys)
}

fn find_in_expr<'a>(expr: &'a Expr<'a>) -> Result<Vec<Key>, minijinja::Error> {
    let mut keys = Vec::new();

    match expr {
        Expr::Var(_var) => {}
        Expr::Const(_const) => {}
        Expr::Slice(slice) => {
            keys.extend(find_in_expr(&slice.expr)?);
            keys.extend(find_in_optional_expr(&slice.start)?);
            keys.extend(find_in_optional_expr(&slice.stop)?);
            keys.extend(find_in_optional_expr(&slice.step)?);
        }
        Expr::UnaryOp(unary_op) => {
            keys.extend(find_in_expr(&unary_op.expr)?);
        }
        Expr::BinOp(bin_op) => {
            keys.extend(find_in_expr(&bin_op.left)?);
            keys.extend(find_in_expr(&bin_op.right)?);
        }
        Expr::IfExpr(if_expr) => {
            keys.extend(find_in_expr(&if_expr.test_expr)?);
            keys.extend(find_in_expr(&if_expr.true_expr)?);
            keys.extend(find_in_optional_expr(&if_expr.false_expr)?);
        }
        Expr::Filter(filter) => {
            keys.extend(find_in_optional_expr(&filter.expr)?);
            keys.extend(find_in_exprs(&filter.args)?);
        }
        Expr::Test(test) => {
            keys.extend(find_in_expr(&test.expr)?);
            keys.extend(find_in_exprs(&test.args)?);
        }
        Expr::GetAttr(get_attr) => {
            keys.extend(find_in_expr(&get_attr.expr)?);
        }
        Expr::GetItem(get_item) => {
            keys.extend(find_in_expr(&get_item.expr)?);
            keys.extend(find_in_expr(&get_item.subscript_expr)?);
        }
        Expr::Call(call) => {
            keys.extend(find_in_call(call)?);
        }
        Expr::List(list) => {
            keys.extend(find_in_exprs(&list.items)?);
        }
        Expr::Map(map) => {
            keys.extend(find_in_exprs(&map.keys)?);
            keys.extend(find_in_exprs(&map.values)?);
        }
        Expr::Kwargs(kwargs) => {
            for (_key, value) in &kwargs.pairs {
                keys.extend(find_in_expr(value)?);
            }
        }
    }

    Ok(keys)
}

fn find_in_exprs<'a>(exprs: &'a [Expr<'a>]) -> Result<Vec<Key>, minijinja::Error> {
    let mut keys = Vec::new();

    for expr in exprs {
        keys.extend(find_in_expr(expr)?);
    }

    Ok(keys)
}

fn find_in_optional_expr<'a>(expr: &'a Option<Expr<'a>>) -> Result<Vec<Key>, minijinja::Error> {
    let mut keys = Vec::new();

    if let Some(expr) = expr {
        keys.extend(find_in_expr(expr)?);
    }

    Ok(keys)
}
