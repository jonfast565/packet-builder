//! Validation written on fields: `== value`, `in lo..hi`, `: Category strict`
//! and `lenient`.

use super::context::Ctx;
use super::versions::{VRange, value_at, version_test};
use crate::ast::{Constraint, ExprNode, FieldRules, Span};
use crate::errors::Diagnostic;
use crate::ir::expr::{CmpOp, LogicOp, TExpr, Ty};
use crate::ir::model::{Check, CheckKind, ValueType};

/// Both version tests, when there are any.
fn and_when(a: &Option<TExpr>, b: Option<TExpr>) -> Option<TExpr> {
    match (a.clone(), b) {
        (Some(a), Some(b)) => Some(TExpr::Logic { op: LogicOp::And, a: Box::new(a), b: Box::new(b) }),
        (a, b) => a.or(b),
    }
}

/// `v` as written in messages: decimal, with hex for larger values.
fn shown(v: i64) -> String {
    if v < 10 { v.to_string() } else { format!("{} (0x{:x})", v, v) }
}

fn cmp(op: CmpOp, member: usize, v: i64) -> TExpr {
    TExpr::Cmp { op, a: Box::new(TExpr::Ref { member, ty: Ty::Int }), b: Box::new(TExpr::IntLit(v)) }
}

impl Ctx<'_> {
    /// Turn a field's validation rules into checks on member `name`.
    pub fn rules(&mut self, name: &str, rules: &FieldRules, is_array: bool, derived: bool, span: Span) {
        if *rules == FieldRules::default() {
            return;
        }
        if derived && rules.lenient && rules == &(FieldRules { lenient: true, ..FieldRules::default() }) {
            // `lenient` on a derived field with no other checks: only
            // verification is relaxed.
            if let Some(&idx) = self.names.get(name) {
                self.members[idx].lenient = true;
            }
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
                    let latest = self.consts.latest.unwrap_or(1);
                    let cond = cat
                        .members
                        .iter()
                        .flat_map(|c| {
                            // A versioned member: its value, in its versions.
                            if c.versions.is_empty() {
                                return vec![cmp(CmpOp::Eq, idx, c.value)];
                            }
                            c.versions
                                .iter()
                                .map(|v| {
                                    let held = cmp(CmpOp::Eq, idx, v.value);
                                    if v.from <= 1 && v.to >= latest {
                                        held
                                    } else {
                                        let when = version_test(VRange { from: v.from, to: v.to }, latest);
                                        TExpr::Logic { op: LogicOp::And, a: Box::new(when), b: Box::new(held) }
                                    }
                                })
                                .collect()
                        })
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
        if let Some(c) = &rules.constraint {
            self.constraint_checks(c, idx, name, None, span, &mut checks);
        }
        if rules.lenient && checks.is_empty() && !derived {
            self.diags.push(Diagnostic::new(format!("`lenient` on `{}` has no check to relax", name), span));
        }
        let m = &mut self.members[idx];
        m.checks = checks;
        m.lenient = rules.lenient;
    }

    /// The checks of `== value` or `in lo..hi` on member `idx`, only for the
    /// versions `when` (a boolean expression) holds in, if given. A value
    /// that depends on the version (a versioned constant) gives one check
    /// per run of versions with the same value.
    fn constraint_checks(
        &mut self,
        c: &Constraint,
        idx: usize,
        name: &str,
        when: Option<TExpr>,
        span: Span,
        checks: &mut Vec<Check>,
    ) {
        let guard = |cond: TExpr, when: &Option<TExpr>| match when {
            None => cond,
            Some(w) => TExpr::Logic {
                op: LogicOp::Or,
                a: Box::new(TExpr::Unary { op: crate::ir::expr::UnaryOp::Not, e: Box::new(w.clone()), ty: Ty::Bool }),
                b: Box::new(cond),
            },
        };
        match c {
            Constraint::Versioned(list) => {
                for (versions, inner) in list {
                    let Some(w) = self.check_expr(versions, span) else { continue };
                    let w = match &when {
                        Some(outer) => TExpr::Logic { op: LogicOp::And, a: Box::new(outer.clone()), b: Box::new(w) },
                        None => w,
                    };
                    self.constraint_checks(inner, idx, name, Some(w), span, checks);
                }
            }
            Constraint::Equals(e) => {
                for (v, w) in self.constant_runs(e, name, span) {
                    let when = and_when(&when, w);
                    checks.push(Check {
                        kind: CheckKind::Equals(v),
                        cond: guard(cmp(CmpOp::Eq, idx, v), &when),
                        message: format!("`{}` must be {}", name, shown(v)),
                    });
                }
            }
            Constraint::Range(lo, hi) => {
                let (los, his) = (self.constant_runs(lo, name, span), self.constant_runs(hi, name, span));
                if los.len() != 1 || his.len() != 1 {
                    self.diags.push(Diagnostic::new(
                        format!(
                            "the bounds of `in` on `{}` cannot depend on the version; re-declare the check per version",
                            name
                        ),
                        span,
                    ));
                    return;
                }
                let (lo, hi) = (los[0].0, his[0].0);
                if lo > hi {
                    self.diags.push(Diagnostic::new(format!("the range {}..{} of `{}` is empty", lo, hi, name), span));
                }
                let both = TExpr::Logic {
                    op: LogicOp::And,
                    a: Box::new(cmp(CmpOp::Gte, idx, lo)),
                    b: Box::new(cmp(CmpOp::Lte, idx, hi)),
                };
                checks.push(Check {
                    kind: CheckKind::Range(lo, hi),
                    cond: guard(both, &when),
                    message: format!("`{}` must be in {}..{}", name, lo, hi),
                });
            }
        }
    }

    /// A constant integer expression that fits member `name`: one value, or
    /// for a value that depends on the version, each value with the test for
    /// its versions (the latest first).
    fn constant_runs(&mut self, e: &ExprNode, name: &str, span: Span) -> Vec<(i64, Option<TExpr>)> {
        let Some(t) = self.check_expr(e, span) else { return Vec::new() };
        if let Some(v) = t.const_int() {
            return self.fits(v, name, span).map(|v| vec![(v, None)]).unwrap_or_default();
        }
        let Some(latest) = self.consts.latest else {
            self.diags.push(Diagnostic::new(
                format!("the value checked on `{}` must be a constant integer expression", name),
                span,
            ));
            return Vec::new();
        };
        let mut runs: Vec<(VRange, i64)> = Vec::new();
        for v in 1..=latest {
            let Some(x) = value_at(&t, v) else {
                self.diags.push(Diagnostic::new(
                    format!("the value checked on `{}` must be a constant integer expression", name),
                    span,
                ));
                return Vec::new();
            };
            match runs.last_mut() {
                Some((r, last)) if *last == x => r.to = v,
                _ => runs.push((VRange { from: v, to: v }, x)),
            }
        }
        if runs.len() == 1 {
            return self.fits(runs[0].1, name, span).map(|v| vec![(v, None)]).unwrap_or_default();
        }
        runs.into_iter()
            .rev()
            .filter_map(|(r, v)| self.fits(v, name, span).map(|v| (v, Some(version_test(r, latest)))))
            .collect()
    }

    /// `v`, if it fits member `name`.
    fn fits(&mut self, v: i64, name: &str, span: Span) -> Option<i64> {
        let ty = &self.members[self.names[name]].ty;
        if !ty.holds(v) {
            self.diags.push(Diagnostic::new(format!("{} does not fit `{}`", v, name), span));
            return None;
        }
        Some(v)
    }
}
