//! Protocol versions (`version 3`, `@2..` before a declaration): resolves
//! every range and rewrites the parse tree so that the other passes only see
//!
//! - a resolved range on the items laid out for some versions only (the
//!   lay-out pass wraps their steps in a gate);
//! - one derivation and one set of checks per field name, as guard chains
//!   over `version` (a re-declaration, or an override such as
//!   `@3 retries = 5`, changes them for its versions);
//! - guards instead of ranges on `calc` and `assert`.
//!
//! A file without `version` is returned unchanged.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::ast::{
    Constraint, ExprNode, FieldRules, PacketExpr, PacketExprList, PacketItem, Span, TypeExpr, VersionRange,
};
use crate::errors::Diagnostic;
use crate::ir::expr::{CmpOp, LogicOp, TExpr};

/// The builtin naming the version being decoded or encoded.
pub(super) const VERSION: &str = "version";

/// An inclusive range of versions, both ends known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VRange {
    pub from: u32,
    pub to: u32,
}

/// `version`, as an expression.
fn version() -> ExprNode {
    ExprNode::ValueReference(VERSION.into(), None)
}

fn lit(v: u32) -> Box<ExprNode> {
    Box::new(ExprNode::UnsignedInteger64Value(v as u64))
}

/// `version` is in `r` (`true` for every version).
pub(super) fn in_range(r: VRange, latest: u32) -> ExprNode {
    let lo = (r.from > 1).then(|| ExprNode::Gte(Box::new(version()), lit(r.from)));
    let hi = (r.to < latest).then(|| ExprNode::Lte(Box::new(version()), lit(r.to)));
    match (lo, hi) {
        (Some(a), Some(b)) => ExprNode::And(Box::new(a), Box::new(b)),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => ExprNode::Equals(lit(0), lit(0)),
    }
}

/// `version` is in `r`, as a typed expression (`true` for every version).
pub fn version_test(r: VRange, latest: u32) -> TExpr {
    let cmp = |op, v: u32| TExpr::Cmp { op, a: Box::new(TExpr::Version), b: Box::new(TExpr::IntLit(v as i64)) };
    let lo = (r.from > 1).then(|| cmp(CmpOp::Gte, r.from));
    let hi = (r.to < latest).then(|| cmp(CmpOp::Lte, r.to));
    match (lo, hi) {
        (Some(a), Some(b)) => TExpr::Logic { op: LogicOp::And, a: Box::new(a), b: Box::new(b) },
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => TExpr::Cmp { op: CmpOp::Eq, a: Box::new(TExpr::IntLit(0)), b: Box::new(TExpr::IntLit(0)) },
    }
}

/// The value of `e` at version `v`, when it uses nothing but constants
/// and `version` (booleans are 0 or 1).
pub fn value_at(e: &TExpr, v: u32) -> Option<i64> {
    Some(match e {
        TExpr::Version => v as i64,
        TExpr::Guard { cond, then, other, .. } => {
            if value_at(cond, v)? != 0 {
                value_at(then, v)?
            } else {
                value_at(other, v)?
            }
        }
        TExpr::Cmp { op, a, b } => {
            let (a, b) = (value_at(a, v)?, value_at(b, v)?);
            let r = match op {
                CmpOp::Gt => a > b,
                CmpOp::Gte => a >= b,
                CmpOp::Lt => a < b,
                CmpOp::Lte => a <= b,
                CmpOp::Eq => a == b,
                CmpOp::Ne => a != b,
            };
            r as i64
        }
        TExpr::Logic { op, a, b } => {
            let (a, b) = (value_at(a, v)? != 0, value_at(b, v)? != 0);
            (if *op == LogicOp::And { a && b } else { a || b }) as i64
        }
        TExpr::Convert { e, .. } => value_at(e, v)?,
        TExpr::Arith { op, a, b, ty: crate::ir::expr::Ty::Int } => op.apply(value_at(a, v)?, value_at(b, v)?),
        other => other.const_int()?,
    })
}

/// `when version in r1 then e1 otherwise when ... otherwise last`: one value
/// per range (ranges in increasing order, covering what matters).
pub(super) fn chain(segments: &[(VRange, ExprNode)], latest: u32) -> ExprNode {
    let (last, rest) = segments.split_last().expect("at least one segment");
    rest.iter().rev().fold(last.1.clone(), |other, (r, e)| {
        ExprNode::GuardExpression(Box::new(in_range(*r, latest)), Box::new(e.clone()), Box::new(other))
    })
}

/// Resolves the ends of `@range`s for one name: an open start is 1, an open
/// end runs until the next declaration's start (or the latest version).
/// `decls` are (range, span) in source order; returns them in that order.
pub(super) fn resolve_ends(
    decls: &[(Option<VersionRange>, Span)],
    latest: u32,
    what: &str,
    diags: &mut Vec<Diagnostic>,
) -> Vec<VRange> {
    let mut out: Vec<VRange> = Vec::with_capacity(decls.len());
    let mut order: Vec<usize> = (0..decls.len()).collect();
    let start = |i: usize| decls[i].0.and_then(|r| r.from).unwrap_or(1);
    order.sort_by_key(|&i| start(i));
    let mut resolved = vec![VRange { from: 1, to: latest }; decls.len()];
    for (k, &i) in order.iter().enumerate() {
        let (range, span) = decls[i];
        if let Some(r) = range
            && r.from.is_none()
            && r.to.is_none()
        {
            diags.push(Diagnostic::new("a version range needs a version (`@2`, `@2..`, `@..3`, `@2..3`)", r.span));
        }
        let from = start(i);
        let to = match range.and_then(|r| r.to) {
            Some(t) => t,
            None => order.get(k + 1).map(|&j| start(j).saturating_sub(1)).unwrap_or(latest),
        };
        if from < 1 || from > latest || to > latest || from > to {
            diags.push(
                Diagnostic::new(
                    format!("{} is declared for versions {}..{}, outside 1..{}", what, from, to, latest),
                    range.map(|r| r.span).unwrap_or(span),
                )
                .with_note(format!("this file declares `version {}`", latest)),
            );
        }
        resolved[i] = VRange { from, to };
    }
    for w in order.windows(2) {
        let (a, b) = (resolved[w[0]], resolved[w[1]]);
        if a.to >= b.from {
            diags.push(Diagnostic::new(
                format!("{} is declared twice for version {}", what, b.from.max(a.from)),
                decls[w[1]].1,
            ));
        }
    }
    out.extend(resolved);
    out
}

/// The latest version, and whether the file uses versions at all.
pub(super) fn latest(list: &PacketExprList) -> Option<u32> {
    list.version.map(|(n, _)| n)
}

/// Every `@range` written in a file without `version`.
fn stray_ranges(list: &PacketExprList, diags: &mut Vec<Diagnostic>) {
    let mut spans = Vec::new();
    for p in &list.packets {
        spans.extend(p.versions.iter().flatten().map(|r| r.span));
        for it in &p.items {
            if let PacketItem::Switch(sw) = it {
                spans.extend(sw.arms.iter().filter_map(|a| a.versions).map(|r| r.span));
            }
        }
    }
    for c in &list.constants {
        spans.extend(c.versions.map(|r| r.span));
        if let crate::ast::ConstKind::Group(items) = &c.kind {
            spans.extend(items.iter().filter_map(|i| i.versions).map(|r| r.span));
        }
    }
    for p in &list.packets {
        for it in &p.items {
            if let PacketItem::Override(o) = it {
                spans.push(o.span);
            }
        }
    }
    if let Some(span) = spans.first() {
        diags.push(
            Diagnostic::new("version ranges need a `version N` declaration at the top of the file", *span)
                .with_note("e.g. `version 3`: the protocol has versions 1..3"),
        );
    }
}

pub(super) fn normalize<'l>(list: &'l PacketExprList, diags: &mut Vec<Diagnostic>) -> Cow<'l, PacketExprList> {
    let Some(latest) = latest(list) else {
        stray_ranges(list, diags);
        return Cow::Borrowed(list);
    };
    if latest == 0 {
        diags.push(Diagnostic::new("`version` must be at least 1", list.version.expect("versioned").1));
        return Cow::Borrowed(list);
    }
    let mut out = list.clone();
    for p in &mut out.packets {
        normalize_packet(p, latest, diags);
    }
    Cow::Owned(out)
}

/// The name an item declares, for grouping re-declarations.
fn item_name(it: &PacketItem) -> Option<&str> {
    match it {
        PacketItem::Field(f) if f.id != "_" => Some(&f.id),
        PacketItem::Bitfield(b) => Some(&b.id),
        PacketItem::Calculated(c) => Some(&c.name),
        PacketItem::Switch(sw) => Some(&sw.id),
        _ => None,
    }
}

fn item_span(it: &PacketItem) -> Span {
    match it {
        PacketItem::Field(f) => f.span,
        PacketItem::Bitfield(b) => b.span,
        PacketItem::Calculated(c) => c.span,
        PacketItem::Switch(sw) => sw.span,
        PacketItem::Assert(a) => a.span,
        PacketItem::Align(_, s) => *s,
        PacketItem::Override(o) => o.span,
    }
}

fn normalize_packet(p: &mut PacketExpr, latest: u32, diags: &mut Vec<Diagnostic>) {
    let n = p.items.len();
    let mut resolved: Vec<Option<VRange>> = vec![None; n];

    // Declarations grouped by name (overrides apart), in source order.
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut overrides: HashMap<String, Vec<usize>> = HashMap::new();
    let mut names: Vec<String> = Vec::new();
    for (i, it) in p.items.iter().enumerate() {
        if let PacketItem::Override(o) = it {
            if p.versions[i].is_none() {
                diags.push(Diagnostic::new(
                    format!("`{}` has no type, so it changes an existing field: start it with a version range", o.id),
                    o.span,
                ));
            }
            overrides.entry(o.id.clone()).or_default().push(i);
        } else if let Some(name) = item_name(it) {
            if !groups.contains_key(name) {
                names.push(name.to_string());
            }
            groups.entry(name.to_string()).or_default().push(i);
        } else if let Some(r) = p.versions[i] {
            // `align` and `assert`: a single declaration.
            let what = if matches!(it, PacketItem::Assert(_)) { "this assertion" } else { "this `align`" };
            resolved[i] = Some(resolve_ends(&[(Some(r), item_span(it))], latest, what, diags)[0]);
        }
    }

    for name in &names {
        let idxs = &groups[name];
        let kinds_differ =
            idxs.windows(2).any(|w| std::mem::discriminant(&p.items[w[0]]) != std::mem::discriminant(&p.items[w[1]]));
        if kinds_differ {
            diags.push(Diagnostic::new(
                format!("`{}` is re-declared as a different kind of field; use a new name", name),
                item_span(&p.items[idxs[1]]),
            ));
            continue;
        }
        if idxs.len() > 1 && idxs.iter().all(|&i| p.versions[i].is_none()) {
            // Not versioned: the usual duplicate error comes later.
            continue;
        }
        let decls: Vec<_> = idxs.iter().map(|&i| (p.versions[i], item_span(&p.items[i]))).collect();
        let ranges = resolve_ends(&decls, latest, &format!("`{}`", name), diags);
        for (&i, r) in idxs.iter().zip(&ranges) {
            resolved[i] = Some(*r);
        }
        match &p.items[idxs[0]] {
            PacketItem::Field(_) => merge_fields(p, name, idxs, &ranges, overrides.remove(name), latest, diags),
            PacketItem::Switch(_) if idxs.len() > 1 => merge_unions(p, name, idxs, &ranges, latest, diags),
            PacketItem::Calculated(_) => merge_calcs(p, idxs, &ranges, latest),
            _ => {}
        }
    }
    for (name, os) in overrides {
        diags.push(Diagnostic::new(format!("`{}` changes a field this packet does not have", name), {
            let PacketItem::Override(o) = &p.items[os[0]] else { unreachable!() };
            o.span
        }));
    }

    // Arms of unions.
    for it in &mut p.items {
        if let PacketItem::Switch(sw) = it {
            for arm in &mut sw.arms {
                if let Some(r) = arm.versions {
                    let s = resolve_ends(&[(Some(r), arm.span)], latest, &format!("arm `{}`", arm.name), diags)[0];
                    arm.versions = Some(VersionRange { from: Some(s.from), to: Some(s.to), span: r.span });
                }
            }
        }
    }

    // Guards for `calc` and `assert`; ranges for the rest. Items for every
    // version need no gate.
    let mut keep = Vec::with_capacity(n);
    let mut versions = Vec::with_capacity(n);
    for (i, it) in std::mem::take(&mut p.items).into_iter().enumerate() {
        let r = resolved[i].filter(|r| !(r.from == 1 && r.to == latest));
        match it {
            PacketItem::Override(_) => continue,
            PacketItem::Calculated(c) if c.name.is_empty() => continue, // merged away
            PacketItem::Assert(mut a) if r.is_some() => {
                let cond = in_range(r.expect("checked"), latest);
                a.expr = ExprNode::Or(Box::new(ExprNode::Not(Box::new(cond))), Box::new(a.expr));
                keep.push(PacketItem::Assert(a));
                versions.push(None);
            }
            PacketItem::Calculated(c) => {
                keep.push(PacketItem::Calculated(c));
                versions.push(None);
            }
            other => {
                keep.push(other);
                versions.push(r.map(|r| VersionRange { from: Some(r.from), to: Some(r.to), span: Span::default() }));
            }
        }
    }
    p.items = keep;
    p.versions = versions;
}

/// Every declaration of field `name` gets the same derivation and checks:
/// guard chains over the versions each one (or an override) covers.
fn merge_fields(
    p: &mut PacketExpr,
    name: &str,
    idxs: &[usize],
    ranges: &[VRange],
    overrides: Option<Vec<usize>>,
    latest: u32,
    diags: &mut Vec<Diagnostic>,
) {
    let fields: Vec<&TypeExpr> = idxs
        .iter()
        .map(|&i| match &p.items[i] {
            PacketItem::Field(f) => f,
            _ => unreachable!("grouped by kind"),
        })
        .collect();
    if let Some(bad) = fields.iter().skip(1).find(|f| f.array.is_some() != fields[0].array.is_some()) {
        diags.push(Diagnostic::new(
            format!("`{}` must stay an array, or stay a single value, in every version; use a new name", name),
            bad.span,
        ));
        return;
    }
    if let Some(bad) = fields.iter().skip(1).find(|f| f.category != fields[0].category && f.category.is_some()) {
        diags.push(Diagnostic::new(
            format!("`{}` must take its values from the same category in every version", name),
            bad.span,
        ));
    }
    if let Some(bad) = fields.iter().skip(1).find(|f| f.placeholder != fields[0].placeholder) {
        diags.push(Diagnostic::new(format!("the placeholder of `{}` cannot change between versions", name), bad.span));
    }

    // Per version: the derivation and the checks in force.
    let latest_us = latest as usize;
    let mut derive: Vec<Option<ExprNode>> = vec![None; latest_us + 1];
    let mut rules: Vec<Option<FieldRules>> = vec![None; latest_us + 1];
    let mut present = vec![false; latest_us + 1];
    for (f, r) in fields.iter().zip(ranges) {
        for v in r.from..=r.to.min(latest) {
            present[v as usize] = true;
            derive[v as usize] = f.derive.clone();
            rules[v as usize] = Some(f.rules.clone());
        }
    }
    if let Some(os) = &overrides {
        let decls: Vec<_> = os
            .iter()
            .map(|&i| {
                let PacketItem::Override(o) = &p.items[i] else { unreachable!() };
                (p.versions[i], o.span)
            })
            .collect();
        let oranges = resolve_ends(&decls, latest, &format!("a change of `{}`", name), diags);
        for (&i, r) in os.iter().zip(&oranges) {
            let PacketItem::Override(o) = &p.items[i] else { unreachable!() };
            for v in r.from..=r.to.min(latest) {
                if !present[v as usize] {
                    diags.push(Diagnostic::new(
                        format!("`{}` changes a field that version {} does not have", name, v),
                        o.span,
                    ));
                    break;
                }
                if o.derive.is_some() {
                    if derive[v as usize].is_none() {
                        diags.push(
                            Diagnostic::new(format!("`{}` is not derived, so `=` cannot change it", name), o.span)
                                .with_note("re-declare it with its type to make it derived"),
                        );
                        break;
                    }
                    derive[v as usize] = o.derive.clone();
                }
                if let Some(c) = &o.rules.constraint {
                    let r = rules[v as usize].get_or_insert_with(FieldRules::default);
                    r.constraint = Some(c.clone());
                    r.lenient |= o.rules.lenient;
                }
            }
        }
    }

    let versions: Vec<u32> = (1..=latest).filter(|&v| present[v as usize]).collect();
    if versions.is_empty() {
        return; // only outside the versions: reported already
    }
    let derived: Vec<bool> = versions.iter().map(|&v| derive[v as usize].is_some()).collect();
    if derived.iter().any(|d| *d) && !derived.iter().all(|d| *d) {
        diags.push(Diagnostic::new(
            format!("`{}` must be derived (`= ...`) in every version it exists in, or in none", name),
            fields[0].span,
        ));
        return;
    }
    let merged_derive =
        derived[0].then(|| chain(&segments(&versions, |v| derive[v as usize].clone().expect("derived")), latest));

    // Checks: one entry per run of versions with the same constraint.
    let constraint_runs = segments(&versions, |v| rules[v as usize].as_ref().and_then(|r| r.constraint.clone()));
    let constraint = if constraint_runs.iter().all(|(_, c)| c.is_none()) {
        None
    } else if constraint_runs.len() == 1 {
        constraint_runs[0].1.clone()
    } else {
        Some(Constraint::Versioned(
            constraint_runs
                .into_iter()
                .filter_map(|(r, c)| c.map(|c| (in_range(r, latest), c)))
                .rev() // the latest first: it gives the field its default
                .collect(),
        ))
    };
    let strict = fields.iter().any(|f| f.rules.strict);
    let lenient = versions.iter().any(|&v| rules[v as usize].as_ref().is_some_and(|r| r.lenient));
    let category = fields.iter().find_map(|f| f.category.clone());

    for &i in idxs {
        if let PacketItem::Field(f) = &mut p.items[i] {
            f.derive = merged_derive.clone();
            f.rules = FieldRules { strict, constraint: constraint.clone(), lenient };
            f.category = category.clone();
        }
    }
}

/// A union declared again for other versions (another selector, other
/// arms): every declaration gets all the arms, each limited to the versions
/// it exists in, so that they share one union type. Each declaration keeps
/// its own selector and position.
fn merge_unions(
    p: &mut PacketExpr,
    name: &str,
    idxs: &[usize],
    ranges: &[VRange],
    latest: u32,
    diags: &mut Vec<Diagnostic>,
) {
    use crate::ast::ArmExpr;
    let mut merged: Vec<(ArmExpr, VRange)> = Vec::new();
    for (&i, decl) in idxs.iter().zip(ranges) {
        let PacketItem::Switch(sw) = &p.items[i] else { unreachable!("grouped by kind") };
        for arm in &sw.arms {
            // The arm's own range, within its declaration's.
            let own = arm.versions.map(|r| VRange { from: r.from.unwrap_or(1), to: r.to.unwrap_or(latest) });
            let r = match own {
                Some(o) => VRange { from: o.from.max(decl.from), to: o.to.min(decl.to) },
                None => *decl,
            };
            if r.from > r.to {
                continue;
            }
            match merged.iter_mut().find(|(a, _)| a.name == arm.name) {
                Some((a, ar)) => {
                    if a.ty != arm.ty || a.values != arm.values || a.args != arm.args {
                        diags.push(Diagnostic::new(
                            format!(
                                "arm `{}` of `{}` changes between versions; give the new one another name",
                                arm.name, name
                            ),
                            arm.span,
                        ));
                    } else if r.from == ar.to + 1 || ar.from == r.to + 1 {
                        *ar = VRange { from: ar.from.min(r.from), to: ar.to.max(r.to) };
                    } else {
                        diags.push(Diagnostic::new(
                            format!("arm `{}` of `{}` must exist in consecutive versions", arm.name, name),
                            arm.span,
                        ));
                    }
                }
                None => merged.push((arm.clone(), r)),
            }
        }
    }
    let arms: Vec<ArmExpr> = merged
        .into_iter()
        .map(|(mut a, r)| {
            let every = r.from <= 1 && r.to >= latest;
            a.versions = (!every).then_some(VersionRange { from: Some(r.from), to: Some(r.to), span: a.span });
            a
        })
        .collect();
    for &i in idxs {
        if let PacketItem::Switch(sw) = &mut p.items[i] {
            sw.arms = arms.clone();
        }
    }
}

/// Runs of consecutive versions (from `versions`, increasing) with equal values.
fn segments<T: PartialEq>(versions: &[u32], value: impl Fn(u32) -> T) -> Vec<(VRange, T)> {
    let mut out: Vec<(VRange, T)> = Vec::new();
    for &v in versions {
        let x = value(v);
        match out.last_mut() {
            Some((r, last)) if *last == x && r.to + 1 == v => r.to = v,
            _ => out.push((VRange { from: v, to: v }, x)),
        }
    }
    out
}

/// Re-declared calculated fields become one, with a guard chain; a single
/// one for some versions only is 0 in the others.
fn merge_calcs(p: &mut PacketExpr, idxs: &[usize], ranges: &[VRange], latest: u32) {
    let mut segs: Vec<(VRange, ExprNode)> = idxs
        .iter()
        .zip(ranges)
        .map(|(&i, r)| match &p.items[i] {
            PacketItem::Calculated(c) => (*r, (*c.expr).clone()),
            _ => unreachable!("grouped by kind"),
        })
        .collect();
    segs.sort_by_key(|(r, _)| r.from);
    let covers_all = segs.first().is_some_and(|(r, _)| r.from == 1)
        && segs.last().is_some_and(|(r, _)| r.to == latest)
        && segs.windows(2).all(|w| w[0].0.to + 1 == w[1].0.from);
    if !covers_all {
        segs.push((VRange { from: 0, to: 0 }, ExprNode::UnsignedInteger64Value(0)));
        // The fallback (0) applies outside every range: make the chain
        // test each range explicitly.
        let last = segs.len() - 1;
        let fallback = segs[last].1.clone();
        let body: Vec<_> = segs[..last].to_vec();
        let e = body.iter().rev().fold(fallback, |other, (r, e)| {
            ExprNode::GuardExpression(Box::new(in_range_exact(*r)), Box::new(e.clone()), Box::new(other))
        });
        set_calc(p, idxs, e);
    } else {
        let e = chain(&segs, latest);
        set_calc(p, idxs, e);
    }
}

/// `version` in `r`, testing both ends.
fn in_range_exact(r: VRange) -> ExprNode {
    ExprNode::And(
        Box::new(ExprNode::Gte(Box::new(version()), lit(r.from))),
        Box::new(ExprNode::Lte(Box::new(version()), lit(r.to))),
    )
}

/// The first declaration keeps the merged expression; the others are dropped.
fn set_calc(p: &mut PacketExpr, idxs: &[usize], e: ExprNode) {
    for (k, &i) in idxs.iter().enumerate() {
        if let PacketItem::Calculated(c) = &mut p.items[i] {
            if k == 0 {
                *c.expr = e.clone();
            } else {
                c.name.clear();
            }
        }
    }
}
