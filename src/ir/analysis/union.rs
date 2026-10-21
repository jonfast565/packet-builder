//! Tagged unions (`body switch kind { ... }`) and windows (`size n`).

use std::collections::{HashMap, HashSet};

use super::cursor::Cursor;
use super::packet::PacketBuilder;
use super::types::value_type;
use super::versions::{VRange, value_at, version_test};
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
        // For each arm: its values in each range of versions it exists in.
        let mut runs: Vec<Vec<(VRange, Vec<i64>)>> = Vec::new();
        let mut names = HashSet::new();
        let mut min_bits = u64::MAX;
        let mut open = false;
        for a in &sw.arms {
            if !names.insert(a.name.clone()) {
                self.ctx
                    .diags
                    .push(Diagnostic::new(format!("union `{}` has two arms named `{}`", sw.id, a.name), a.span));
            }
            let arm_runs = self.arm_values(a);
            // The values in the latest version the arm has (the only one
            // without versions).
            let values = arm_runs.last().map(|(_, v)| v.clone()).unwrap_or_default();
            runs.push(arm_runs);
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
        self.check_arm_values(sw, &runs);
        let selector = self.gate_arms(sw, &mut arms, &runs, selector);
        self.steps.push(Step::Switch { member, selector, arms });
        self.available.insert(member);
    }

    /// The values of arm `a` in each range of versions it exists in (one
    /// range without versions). Versioned constants give a value per
    /// version, as do re-declarations that change them.
    fn arm_values(&mut self, a: &crate::ast::ArmExpr) -> Vec<(VRange, Vec<i64>)> {
        let Some(exprs) = &a.values else { return Vec::new() };
        let latest = self.ctx.consts.latest;
        let all = VRange { from: 1, to: latest.unwrap_or(1) };
        let own = a.versions.map(|r| VRange { from: r.from.unwrap_or(1), to: r.to.unwrap_or(all.to) }).unwrap_or(all);
        let decls: Vec<(VRange, &Vec<crate::ast::ExprNode>)> = if a.by_version.is_empty() {
            vec![(own, exprs)]
        } else {
            a.by_version.iter().map(|(f, t, e)| (VRange { from: *f, to: *t }, e)).collect()
        };
        let mut out: Vec<(VRange, Vec<i64>)> = Vec::new();
        for (r, exprs) in decls {
            let typed: Vec<TExpr> = exprs.iter().filter_map(|e| self.ctx.check_expr(e, a.span)).collect();
            for v in r.from..=r.to {
                let mut vals = Vec::new();
                for t in &typed {
                    match t.const_int().or_else(|| latest.and_then(|_| value_at(t, v))) {
                        Some(x) => vals.push(x),
                        None => {
                            self.ctx.diags.push(Diagnostic::new(
                                format!("the values of arm `{}` must be constant integers", a.name),
                                a.span,
                            ));
                            return out;
                        }
                    }
                }
                match out.last_mut() {
                    Some((rr, last)) if *last == vals && rr.to + 1 == v => rr.to = v,
                    _ => out.push((VRange { from: v, to: v }, vals)),
                }
            }
        }
        out
    }

    /// No value may select two arms in the same version.
    fn check_arm_values(&mut self, sw: &SwitchExpr, runs: &[Vec<(VRange, Vec<i64>)>]) {
        let mut seen: HashMap<(u32, i64), usize> = HashMap::new();
        let mut reported = HashSet::new();
        for (i, arm_runs) in runs.iter().enumerate() {
            for (r, vals) in arm_runs {
                for v in r.from..=r.to {
                    for &x in vals {
                        if let Some(&other) = seen.get(&(v, x))
                            && other != i
                            && reported.insert((x, other, i))
                        {
                            let (a, b) = (&sw.arms[other].name, &sw.arms[i].name);
                            self.ctx.diags.push(Diagnostic::new(
                                format!("value {} selects both `{}` and `{}`", x, a, b),
                                sw.arms[i].span,
                            ));
                        }
                        seen.insert((v, x), i);
                    }
                }
            }
        }
    }

    /// Arms whose values are not the same in every version (an arm for some
    /// versions only, values that change, a value two arms of different
    /// versions share): the selector maps them to what the arm tests see.
    /// An arm missing from a version maps its values to one no arm lists, so
    /// they fall to the default arm (or fail when there is none); an arm
    /// whose values change, or that shares one, gets a value of its own,
    /// which the selector maps to in each of its versions.
    fn gate_arms(
        &mut self,
        sw: &SwitchExpr,
        arms: &mut [Arm],
        runs: &[Vec<(VRange, Vec<i64>)>],
        selector: TExpr,
    ) -> TExpr {
        let Some(latest) = self.ctx.consts.latest else { return selector };
        let mut used: HashSet<i64> = runs.iter().flatten().flat_map(|(_, v)| v.iter().copied()).collect();
        let mut fresh = || {
            let v = (1..).map(|n: i64| -n).find(|v| !used.contains(v)).unwrap_or(-1);
            used.insert(v);
            v
        };
        let nothing = fresh();
        let mut owners = HashMap::<i64, HashSet<usize>>::new();
        for (i, arm_runs) in runs.iter().enumerate() {
            for v in arm_runs.iter().flat_map(|(_, vals)| vals) {
                owners.entry(*v).or_default().insert(i);
            }
        }
        let sel_in = |vals: &[i64]| {
            vals.iter()
                .map(|v| TExpr::Cmp { op: CmpOp::Eq, a: Box::new(selector.clone()), b: Box::new(TExpr::IntLit(*v)) })
                .reduce(|x, y| TExpr::Logic { op: LogicOp::Or, a: Box::new(x), b: Box::new(y) })
        };
        let mut out = selector.clone();
        for (i, (a, arm)) in sw.arms.iter().zip(arms.iter_mut()).enumerate() {
            if arm.default {
                if a.versions.is_some_and(|r| r.from.unwrap_or(1) > 1 || r.to.unwrap_or(latest) < latest) {
                    self.ctx.diags.push(Diagnostic::new("the `_` arm cannot have a version range", a.span));
                }
                continue;
            }
            let arm_runs = &runs[i];
            let every = arm_runs.len() == 1 && arm_runs[0].0.from <= 1 && arm_runs[0].0.to >= latest;
            if every || arm_runs.is_empty() {
                continue;
            }
            let shared = arm_runs.iter().flat_map(|(_, v)| v).any(|v| owners[v].len() > 1);
            if arm_runs.len() > 1 || shared {
                let own = fresh();
                arm.values = vec![own];
                for (r, vals) in arm_runs {
                    let Some(picks) = sel_in(vals) else { continue };
                    let cond =
                        TExpr::Logic { op: LogicOp::And, a: Box::new(version_test(*r, latest)), b: Box::new(picks) };
                    out = TExpr::Guard {
                        cond: Box::new(cond),
                        then: Box::new(TExpr::IntLit(own)),
                        other: Box::new(out),
                        ty: Ty::Int,
                    };
                }
            } else {
                let (r, vals) = &arm_runs[0];
                let Some(picks) = sel_in(vals) else { continue };
                let absent = TExpr::Unary { op: UnaryOp::Not, e: Box::new(version_test(*r, latest)), ty: Ty::Bool };
                let cond = TExpr::Logic { op: LogicOp::And, a: Box::new(absent), b: Box::new(picks) };
                out = TExpr::Guard {
                    cond: Box::new(cond),
                    then: Box::new(TExpr::IntLit(nothing)),
                    other: Box::new(out),
                    ty: Ty::Int,
                };
            }
        }
        out
    }
}
