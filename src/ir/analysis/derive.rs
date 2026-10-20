//! Derived fields (`length uint16 = len(payload)`, `crc uint16 =
//! crc16_arc(a..b)`): type-checking, the positions they read, and the order
//! in which encoding computes and patches them.

use std::collections::{HashMap, HashSet};

use super::packet::PacketBuilder;
use crate::ast::PacketItem;
use crate::errors::Diagnostic;
use crate::ir::expr::{Mark, TExpr, Ty, coerce};
use crate::ir::model::{Codec, Count, MemberKind, Step, StrMode, ValueType};

/// What the analysis decides about a packet's derived fields.
pub(super) struct DerivedPlan {
    pub derived: Vec<usize>,
    pub patches: Vec<usize>,
    pub wire_dependent: Vec<usize>,
    pub encode_calcs: Vec<usize>,
}

/// The first and last step (or item) a range covers; `usize::MAX` for the
/// end of the packet.
fn span_of(from: Mark, to: Mark) -> (usize, usize) {
    let first = match from {
        Mark::PacketStart => 0,
        Mark::Before(i) => i,
        Mark::After(i) => i + 1,
        Mark::PacketEnd => usize::MAX,
    };
    let last = match to {
        Mark::PacketStart => 0,
        Mark::Before(i) => i.wrapping_sub(1),
        Mark::After(i) => i,
        Mark::PacketEnd => usize::MAX,
    };
    (first, last)
}

/// Order `nodes` so that each comes after the nodes `before(n)` returns
/// (restricted to `nodes`). Returns a node of a cycle on failure.
fn topo(nodes: &[usize], before: impl Fn(usize) -> Vec<usize>) -> Result<Vec<usize>, usize> {
    fn visit(
        n: usize,
        nodes: &HashSet<usize>,
        before: &dyn Fn(usize) -> Vec<usize>,
        state: &mut HashMap<usize, bool>,
        out: &mut Vec<usize>,
    ) -> Result<(), usize> {
        match state.get(&n) {
            Some(true) => return Ok(()),
            Some(false) => return Err(n),
            None => {}
        }
        state.insert(n, false);
        for d in before(n) {
            if d != n && nodes.contains(&d) {
                visit(d, nodes, before, state, out)?;
            }
        }
        state.insert(n, true);
        out.push(n);
        Ok(())
    }
    let set: HashSet<usize> = nodes.iter().copied().collect();
    let mut state = HashMap::new();
    let mut out = Vec::new();
    for &n in nodes {
        visit(n, &set, &before, &mut state, &mut out)?;
    }
    Ok(out)
}

impl PacketBuilder<'_> {
    /// Pass 3b: the expressions of derived fields. Their marks refer to
    /// source items until `finish_derived` maps them to steps.
    pub(super) fn resolve_derived(&mut self) {
        for (item, it) in self.p.items.iter().enumerate() {
            let PacketItem::Field(f) = it else { continue };
            let Some(e) = &f.derive else { continue };
            if f.id == "_" {
                self.ctx.diags.push(Diagnostic::new("padding (`_`) cannot be derived", f.span));
                continue;
            }
            let Some(&idx) = self.ctx.names.get(&f.id) else { continue };
            if f.array.is_some() || !matches!(self.ctx.members[idx].ty, ValueType::Int { .. }) {
                self.ctx
                    .diags
                    .push(Diagnostic::new(format!("derived field `{}` must be a single integer", f.id), f.span));
                continue;
            }
            self.ctx.allow_wire = true;
            let t = self.ctx.check_expr(e, f.span);
            self.ctx.allow_wire = false;
            let Some(t) = t else { continue };
            let mut t = coerce(t, Ty::Int);
            // A checksum over a range that includes the field itself treats
            // the field's own bytes as zero.
            t.visit_mut(&mut |e| {
                if let TExpr::Checksum { from, to, hole, .. } = e {
                    let (first, last) = span_of(*from, *to);
                    if first <= item && item <= last {
                        *hole = Some((Mark::Before(item), Mark::After(item)));
                    }
                }
            });
            let mut deps = Vec::new();
            t.deps(&mut deps);
            if deps.contains(&idx) {
                self.ctx.diags.push(Diagnostic::new(format!("derived field `{}` uses its own value", f.id), f.span));
                continue;
            }
            self.ctx.members[idx].kind = MemberKind::Derived(t);
        }
    }

    /// After layout: map marks to steps, check them, and decide the order of
    /// encode-time values and patches.
    pub(super) fn finish_derived(&mut self) -> DerivedPlan {
        let by_item = self.item_steps.clone();
        let starts: HashMap<usize, bool> = by_item.values().map(|s| (s.first, s.aligned_before)).collect();
        let ends: HashMap<usize, bool> = by_item.values().map(|s| (s.last, s.aligned_after)).collect();
        let to_step = |m: Mark| match m {
            Mark::Before(i) => Mark::Before(by_item.get(&i).map(|s| s.first).unwrap_or(0)),
            Mark::After(i) => Mark::After(by_item.get(&i).map(|s| s.last).unwrap_or(0)),
            other => other,
        };
        let derived: Vec<usize> = (0..self.ctx.members.len()).filter(|&i| self.ctx.members[i].is_derived()).collect();
        for &i in &derived {
            if let MemberKind::Derived(e) = &mut self.ctx.members[i].kind {
                e.map_marks(&to_step);
            }
        }

        // Positions must be whole bytes.
        let span = self.p.span;
        for &i in &derived {
            let m = &self.ctx.members[i];
            let mut marks = Vec::new();
            if let Some(e) = m.derived_expr() {
                e.marks(&mut marks);
            }
            let unaligned = marks.iter().any(|mk| match mk {
                Mark::Before(s) => starts.get(s).map(|a| !a).unwrap_or(false),
                Mark::After(s) => ends.get(s).map(|a| !a).unwrap_or(false),
                _ => false,
            });
            if unaligned {
                let name = m.name.clone();
                self.ctx.diags.push(
                    Diagnostic::new(
                        format!("`{}` measures a range that does not start and end on byte boundaries", name),
                        span,
                    )
                    .with_note("sizeof, offsetof and checksums work on whole bytes"),
                );
            }
        }

        // Derived fields whose value needs the encoded bytes, directly or
        // through another one.
        let members = &self.ctx.members;
        let deps_of = |i: usize| {
            let mut d = Vec::new();
            if let Some(e) = members[i].derived_expr().or(members[i].calc_expr()) {
                e.deps(&mut d);
            }
            d
        };
        let mut wire: HashSet<usize> = derived
            .iter()
            .copied()
            .filter(|&i| {
                let mut marks = Vec::new();
                members[i].derived_expr().expect("derived").marks(&mut marks);
                !marks.is_empty()
            })
            .collect();
        loop {
            let more: Vec<usize> = (0..members.len())
                .filter(|&i| {
                    !wire.contains(&i)
                        && (members[i].is_derived() || members[i].is_calculated())
                        && deps_of(i).iter().any(|d| wire.contains(d))
                })
                .collect();
            if more.is_empty() {
                break;
            }
            wire.extend(more);
        }
        let mut wire_dependent: Vec<usize> = wire.iter().copied().collect();
        wire_dependent.sort();
        let patched: Vec<usize> = derived.iter().copied().filter(|i| wire.contains(i)).collect();

        // Patch order: after the fields a value reads, and after the fields
        // whose bytes a checksum covers.
        let steps = &self.steps;
        let step_of = |m: usize| steps.iter().position(|s| matches!(s, Step::Field { member: Some(x), .. } if *x == m));
        let patches = match topo(&patched, |a| {
            let mut before = deps_of(a);
            let mut ranges = Vec::new();
            members[a].derived_expr().expect("derived").checksums(&mut ranges);
            for &b in &patched {
                if let Some(s) = step_of(b)
                    && ranges.iter().any(|(f, t)| {
                        let (first, last) = span_of(*f, *t);
                        first <= s && s <= last
                    })
                {
                    before.push(b);
                }
            }
            before
        }) {
            Ok(order) => order,
            Err(n) => {
                let name = members[n].name.clone();
                self.ctx.diags.push(Diagnostic::new(
                    format!("derived field `{}` depends on a field that depends on it", name),
                    span,
                ));
                Vec::new()
            }
        };

        // A varint's size depends on its value, so it cannot be patched.
        for &m in &patched {
            if steps
                .iter()
                .any(|s| matches!(s, Step::Field { member: Some(x), codec: Codec::Varint(_), .. } if *x == m))
            {
                let name = members[m].name.clone();
                self.ctx.diags.push(
                    Diagnostic::new(format!("varint `{}` cannot be derived from the encoded bytes", name), span)
                        .with_note("its size depends on its value; use a fixed-size integer"),
                );
            }
        }

        // Values encoding computes up front: calculated members something
        // needs, and derived members that only depend on values.
        let wire_dep = |e: &TExpr| {
            let mut d = Vec::new();
            e.deps(&mut d);
            d.iter().any(|x| wire.contains(x))
        };
        let mut roots = Vec::new();
        for s in steps {
            if let Step::Field { array: Some(Count::Expr(e)), codec, member, .. } = s {
                if !wire_dep(e) {
                    e.deps(&mut roots);
                } else if matches!(codec, Codec::Str(StrMode::Padded)) {
                    let name = member.map(|m| members[m].name.clone()).unwrap_or_default();
                    self.ctx.diags.push(Diagnostic::new(
                        format!("the size of `{}` depends on a field derived from the encoded bytes", name),
                        span,
                    ));
                }
            }
        }
        for (a, _) in &self.asserts {
            if !wire_dep(&a.cond) {
                a.cond.deps(&mut roots);
            }
        }
        for &i in &derived {
            roots.extend(deps_of(i));
        }
        let mut needed: HashSet<usize> = HashSet::new();
        while let Some(m) = roots.pop() {
            // Calculated members read from `remaining` keep their stored value.
            if members[m].is_calculated() && !members[m].is_decode_only() && needed.insert(m) {
                roots.extend(deps_of(m));
            }
        }
        let mut locals: Vec<usize> = needed.iter().copied().collect();
        locals.extend(derived.iter().copied().filter(|i| !wire.contains(i)));
        locals.sort();
        if let Some(&bad) = locals.iter().find(|i| wire.contains(i)) {
            let name = members[bad].name.clone();
            self.ctx.diags.push(Diagnostic::new(
                format!(
                    "`{}` depends on a field derived from the encoded bytes, so encoding cannot compute it first",
                    name
                ),
                span,
            ));
        }
        let encode_calcs = match topo(&locals, deps_of) {
            Ok(order) => order,
            Err(n) => {
                let name = members[n].name.clone();
                self.ctx.diags.push(Diagnostic::new(format!("`{}` depends on itself", name), span));
                Vec::new()
            }
        };
        DerivedPlan { derived, patches, wire_dependent, encode_calcs }
    }
}
