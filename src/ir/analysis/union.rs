//! Tagged unions (`body switch kind { ... }`) and windows (`size n`).

use std::collections::{HashMap, HashSet};

use super::cursor::Cursor;
use super::packet::PacketBuilder;
use super::types::value_type;
use super::versions::{VRange, version_test};
use crate::ast::{ArrayLength, Span, SwitchExpr, TypeNode, WindowExpr};
use crate::errors::Diagnostic;
use crate::ir::expr::{CmpOp, LogicOp, TExpr, Ty, UnaryOp, coerce};
use crate::ir::model::{Arm, Codec, Count, Step, ValueType};

/// A window opened before a field and closed after it.
pub(super) struct Window {
    step: usize,
    saved: Cursor,
    open_ended: bool,
    constant: Option<i64>,
    exact: bool,
}

impl PacketBuilder<'_> {
    /// `size n` after a field: open a window of n bytes.
    pub(super) fn open_window(&mut self, w: Option<&WindowExpr>, span: Span, name: &str) -> Option<Window> {
        let w = w?;
        if !self.cursor.align.is_aligned() {
            self.ctx
                .diags
                .push(Diagnostic::new(format!("`{}` has a size, so it must start on a byte boundary", name), span));
        }
        let size = self.ctx.check_expr(&w.size, span).map(|t| coerce(t, Ty::Int)).unwrap_or(TExpr::IntLit(0));
        self.ctx.require_available(&size, &self.available, &self.scheduled, span, "size", name);
        let constant = size.const_int();
        self.steps.push(Step::OpenWindow { size, exact: w.exact });
        Some(Window {
            step: self.steps.len() - 1,
            saved: self.cursor,
            open_ended: self.open_ended,
            constant,
            exact: w.exact,
        })
    }

    /// Close a window: whatever the field holds, it takes exactly n bytes.
    pub(super) fn close_window(&mut self, w: Option<Window>) {
        let Some(w) = w else { return };
        self.steps.push(Step::CloseWindow { open: w.step, exact: w.exact });
        self.cursor = w.saved;
        self.open_ended = w.open_ended;
        match w.constant {
            Some(n) if n >= 0 => self.cursor.advance(n as u64 * 8, Some(n as u64 * 8), 1),
            _ => self.cursor.advance_unknown(8),
        }
    }

    /// A tagged union. `is_last` is true for the last field of the packet
    /// or a field inside a window, which may run to the end.
    pub(super) fn lay_out_switch(&mut self, sw: &SwitchExpr, is_last: bool) {
        let span = sw.span;
        if self.open_ended {
            self.ctx.diags.push(Diagnostic::new(
                format!("field `{}` follows a field that consumes the rest of the input", sw.id),
                span,
            ));
        }
        let Some(&member) = self.ctx.names.get(&sw.id) else { return };
        if !self.cursor.align.is_aligned() {
            self.ctx.diags.push(Diagnostic::new(format!("union `{}` must start on a byte boundary", sw.id), span));
        }
        let selector = self.ctx.check_expr(&sw.selector, span).map(|t| coerce(t, Ty::Int)).unwrap_or(TExpr::IntLit(0));
        self.ctx.require_available(&selector, &self.available, &self.scheduled, span, "selector", &sw.id);

        let mut arms = Vec::new();
        let mut seen: HashMap<i64, String> = HashMap::new();
        let mut names = HashSet::new();
        let mut min_bits = u64::MAX;
        let mut open = false;
        for a in &sw.arms {
            if !names.insert(a.name.clone()) {
                self.ctx
                    .diags
                    .push(Diagnostic::new(format!("union `{}` has two arms named `{}`", sw.id, a.name), a.span));
            }
            let mut values = Vec::new();
            if let Some(vs) = &a.values {
                for v in vs {
                    let Some(t) = self.ctx.check_expr(v, a.span) else { continue };
                    let Some(v) = t.const_int() else {
                        self.ctx.diags.push(Diagnostic::new(
                            format!("the values of arm `{}` must be constant integers", a.name),
                            a.span,
                        ));
                        continue;
                    };
                    if let Some(other) = seen.insert(v, a.name.clone()) {
                        // Arms of different versions may share a value.
                        let other_range = sw.arms.iter().find(|x| x.name == other).and_then(|x| x.versions);
                        if !disjoint(a.versions, other_range) {
                            self.ctx.diags.push(Diagnostic::new(
                                format!("value {} selects both `{}` and `{}`", v, other, a.name),
                                a.span,
                            ));
                        }
                    }
                    values.push(v);
                }
            }
            let default = a.values.is_none();
            if default && arms.iter().any(|x: &Arm| x.default) {
                self.ctx.diags.push(Diagnostic::new(format!("union `{}` has two `_` arms", sw.id), a.span));
            }
            let mut arm = Arm { name: a.name.clone(), values, default, ty: None, codec: None, count: None };
            let bits = match &a.ty {
                None => 0,
                Some((TypeNode::Packet(n), None, None)) => {
                    arm.ty = Some(ValueType::Packet(n.clone()));
                    arm.codec = Some(Codec::Packet(self.packet_ref(n, &a.args, a.span, &a.name)));
                    // A packet analyzed later (it contains this one) is not
                    // known yet.
                    match self.ctx.done.get(n) {
                        Some(nested) => {
                            open |= nested.open_ended;
                            nested.min_bits
                        }
                        None => 0,
                    }
                }
                Some((TypeNode::Bytes | TypeNode::UnsignedInteger8, Some(len), endian)) if endian.is_none() => {
                    let count = match len {
                        ArrayLength::Remaining => {
                            open = true;
                            Count::Remaining
                        }
                        ArrayLength::Expr(e) => {
                            let e =
                                self.ctx.check_expr(e, a.span).map(|t| coerce(t, Ty::Int)).unwrap_or(TExpr::IntLit(0));
                            self.ctx.require_available(&e, &self.available, &self.scheduled, a.span, "length", &a.name);
                            Count::Expr(e)
                        }
                    };
                    arm.ty = Some(ValueType::Int { width: 8, signed: false });
                    arm.codec = Some(Codec::Bytes { nbytes: 1, endian: self.default_endian.clone() });
                    arm.count = Some(count);
                    0
                }
                Some((t, None, endian))
                    if t.integer_info().is_some_and(|(w, _)| w % 8 == 0)
                        && !matches!(t, TypeNode::Bytes | TypeNode::Char) =>
                {
                    let align = self.cursor.align;
                    let codec = self.ctx.codec_for(t, endian.clone(), &self.default_endian, align, a.span, &a.name);
                    arm.ty = Some(value_type(t));
                    arm.codec = Some(codec);
                    t.integer_info().map(|(w, _)| w as u64).unwrap_or(0)
                }
                _ => {
                    self.ctx.diags.push(
                        Diagnostic::new(
                            format!(
                                "arm `{}` of union `{}` must hold a packet, an integer, bytes, or nothing",
                                a.name, sw.id
                            ),
                            a.span,
                        )
                        .with_note("wrap lists and strings in a packet"),
                    );
                    0
                }
            };
            min_bits = min_bits.min(bits);
            arms.push(arm);
        }
        if open && !is_last {
            self.ctx.diags.push(
                Diagnostic::new(
                    format!(
                        "union `{}` has an arm that runs to the end of the input, so it must be the last field",
                        sw.id
                    ),
                    span,
                )
                .with_note("give it a size (`... } size length`) or move it to the end"),
            );
        }
        self.open_ended |= open;
        self.aligned_before = self.cursor.align.is_aligned();
        self.cursor.advance(if min_bits == u64::MAX { 0 } else { min_bits }, None, 1);
        self.cursor.advance_unknown(8);
        let selector = self.gate_arms(sw, &mut arms, selector);
        self.steps.push(Step::Switch { member, selector, arms });
        self.available.insert(member);
    }

    /// Arms for some versions only (`@2.. Kind.x => x X`): in the other
    /// versions their values select nothing, so they fall to the default arm
    /// (or fail when there is none); the selector maps them to a value no
    /// arm lists. Arms of different versions that share a value get a value
    /// of their own instead, which the selector maps to in their versions.
    fn gate_arms(&mut self, sw: &SwitchExpr, arms: &mut [Arm], selector: TExpr) -> TExpr {
        let Some(latest) = self.ctx.consts.latest else { return selector };
        let mut used: HashSet<i64> = arms.iter().flat_map(|a| a.values.iter().copied()).collect();
        let mut fresh = || {
            let v = (1..).map(|n: i64| -n).find(|v| !used.contains(v)).unwrap_or(-1);
            used.insert(v);
            v
        };
        let nothing = fresh();
        let shared: Vec<i64> = {
            let mut count = HashMap::<i64, usize>::new();
            for v in arms.iter().flat_map(|a| a.values.iter()) {
                *count.entry(*v).or_default() += 1;
            }
            count.into_iter().filter(|(_, n)| *n > 1).map(|(v, _)| v).collect()
        };
        let mut out = selector.clone();
        for (a, arm) in sw.arms.iter().zip(arms.iter_mut()) {
            let Some(r) = a.versions else { continue };
            let r = VRange { from: r.from.unwrap_or(1), to: r.to.unwrap_or(latest) };
            if arm.default {
                if !(r.from <= 1 && r.to >= latest) {
                    self.ctx.diags.push(Diagnostic::new("the `_` arm cannot have a version range", a.span));
                }
                continue;
            }
            if r.from <= 1 && r.to >= latest {
                continue;
            }
            let picks = arm
                .values
                .iter()
                .map(|v| TExpr::Cmp { op: CmpOp::Eq, a: Box::new(selector.clone()), b: Box::new(TExpr::IntLit(*v)) })
                .reduce(|x, y| TExpr::Logic { op: LogicOp::Or, a: Box::new(x), b: Box::new(y) });
            let Some(picks) = picks else { continue };
            let present = version_test(r, latest);
            let (cond, value) = if arm.values.iter().any(|v| shared.contains(v)) {
                let own = fresh();
                arm.values = vec![own];
                (TExpr::Logic { op: LogicOp::And, a: Box::new(present), b: Box::new(picks) }, own)
            } else {
                let absent = TExpr::Unary { op: UnaryOp::Not, e: Box::new(present), ty: Ty::Bool };
                (TExpr::Logic { op: LogicOp::And, a: Box::new(absent), b: Box::new(picks) }, nothing)
            };
            out = TExpr::Guard {
                cond: Box::new(cond),
                then: Box::new(TExpr::IntLit(value)),
                other: Box::new(out),
                ty: Ty::Int,
            };
        }
        out
    }
}

/// Whether two `@range`s (None: every version) have no version in common.
fn disjoint(a: Option<crate::ast::VersionRange>, b: Option<crate::ast::VersionRange>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let (af, at) = (a.from.unwrap_or(1), a.to.unwrap_or(u32::MAX));
            let (bf, bt) = (b.from.unwrap_or(1), b.to.unwrap_or(u32::MAX));
            at < bf || bt < af
        }
        _ => false,
    }
}
