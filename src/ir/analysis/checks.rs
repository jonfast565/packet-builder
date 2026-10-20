//! Validation written on fields: `== value`, `in lo..hi`, `: Category strict`
//! and `lenient`.

use super::context::Ctx;
use crate::ast::{Constraint, ExprNode, FieldRules, Span};
use crate::errors::Diagnostic;
use crate::ir::expr::{CmpOp, LogicOp, TExpr, Ty};
use crate::ir::model::{Check, CheckKind, ValueType};

/// `v` as written in messages: decimal, with hex for larger values.
fn shown(v: i64) -> String {
    if v < 10 { v.to_string() } else { format!("{} (0x{:x})", v, v) }
}

fn cmp(op: CmpOp, member: usize, v: i64) -> TExpr {
    TExpr::Cmp { op, a: Box::new(TExpr::Ref { member, ty: Ty::Int }), b: Box::new(TExpr::IntLit(v)) }
}

impl Ctx<'_> {
    /// Turn a field's validation rules into checks on member `name`.
    pub fn rules(&mut self, name: &str, rules: &FieldRules, is_array: bool, span: Span) {
        if *rules == FieldRules::default() {
            return;
        }
        if name == "_" {
            self.diags.push(Diagnostic::new("padding (`_`) cannot have checks", span));
            return;
        }
        let Some(&idx) = self.names.get(name) else { return };
        if is_array || !matches!(self.members[idx].ty, ValueType::Int { .. }) {
            self.diags.push(Diagnostic::new(
                format!("`{}` is not a single integer, so it cannot have `==`, `in` or `strict` checks", name),
                span,
            ));
            return;
        }
        let mut checks = Vec::new();
        if rules.strict {
            match self.members[idx].category.clone().and_then(|c| self.consts.category(&c).cloned()) {
                Some(cat) => {
                    let cond = cat
                        .members
                        .iter()
                        .map(|c| cmp(CmpOp::Eq, idx, c.value))
                        .reduce(|a, b| TExpr::Logic { op: LogicOp::Or, a: Box::new(a), b: Box::new(b) })
                        .unwrap_or(TExpr::Cmp {
                            op: CmpOp::Ne,
                            a: Box::new(TExpr::IntLit(0)),
                            b: Box::new(TExpr::IntLit(0)),
                        });
                    checks.push(Check {
                        kind: CheckKind::InCategory(cat.name.clone()),
                        cond,
                        message: format!("`{}` is not one of the values of `{}`", name, cat.name),
                    });
                }
                None => self.diags.push(
                    Diagnostic::new(format!("`strict` on `{}` needs a category", name), span)
                        .with_note("write `: Category strict`"),
                ),
            }
        }
        match &rules.constraint {
            Some(Constraint::Equals(e)) => {
                if let Some(v) = self.constant(e, name, span) {
                    checks.push(Check {
                        kind: CheckKind::Equals(v),
                        cond: cmp(CmpOp::Eq, idx, v),
                        message: format!("`{}` must be {}", name, shown(v)),
                    });
                }
            }
            Some(Constraint::Range(lo, hi)) => {
                if let (Some(lo), Some(hi)) = (self.constant(lo, name, span), self.constant(hi, name, span)) {
                    if lo > hi {
                        self.diags
                            .push(Diagnostic::new(format!("the range {}..{} of `{}` is empty", lo, hi, name), span));
                    }
                    let both = TExpr::Logic {
                        op: LogicOp::And,
                        a: Box::new(cmp(CmpOp::Gte, idx, lo)),
                        b: Box::new(cmp(CmpOp::Lte, idx, hi)),
                    };
                    checks.push(Check {
                        kind: CheckKind::Range(lo, hi),
                        cond: both,
                        message: format!("`{}` must be in {}..{}", name, lo, hi),
                    });
                }
            }
            None => {}
        }
        if rules.lenient && checks.is_empty() {
            self.diags.push(Diagnostic::new(format!("`lenient` on `{}` has no check to relax", name), span));
        }
        let m = &mut self.members[idx];
        m.checks = checks;
        m.lenient = rules.lenient;
    }

    /// A constant integer expression that fits member `name`.
    fn constant(&mut self, e: &ExprNode, name: &str, span: Span) -> Option<i64> {
        let t = self.check_expr(e, span)?;
        let Some(v) = t.const_int() else {
            self.diags.push(Diagnostic::new(
                format!("the value checked on `{}` must be a constant integer expression", name),
                span,
            ));
            return None;
        };
        let ty = &self.members[self.names[name]].ty;
        if !ty.holds(v) {
            self.diags.push(Diagnostic::new(format!("{} does not fit `{}`", v, name), span));
            return None;
        }
        Some(v)
    }
}
