//! Setter views (`generate --access`): for every member that can change
//! without changing the layout, a packet `<Packet>_<member>_set` whose
//! decode, change, encode round trip gives back the input with only that
//! member changed. The bytes the view does not interpret are kept in
//! hidden members (`skipped_<n>`, and `rest` for everything after it), so
//! encoding writes them back unchanged, padding and reserved bits included.
//!
//! When no checksum covers the packet, the view stops at the member, like
//! a field view: what comes before is skipped as raw bytes where its size
//! is known, and everything after it is `rest`. Otherwise (or when the cut
//! would not fall on a byte boundary) the view is the whole packet plus
//! `rest`, so encoding recomputes the checksums and lengths.
//!
//! A member is settable when it is stored (not derived, calculated or the
//! version), has a size that does not depend on its value (a fixed-size
//! scalar, a bitfield part, or an array with a constant count), and no
//! expression of its packet reads it (counts, sizes, selectors, offsets,
//! derived values, assertions, other members' checks). Checksums of an
//! enclosing packet are not recomputed.

use super::expr::{ArithOp, Mark, TExpr};
use super::model::{BitPart, Codec, Count, Member, MemberKind, Module, Packet, Step, StrMode, ValueType};
use super::views::{target_steps, view};
use crate::ast::Endianness;

/// The name of the setter view of member `member` of packet `packet`.
pub fn setter_view_name(packet: &str, member: &str) -> String {
    format!("{}_{}_set", packet, member)
}

/// The setter view of member `m` of `p`, if the member is settable.
pub(super) fn setter_view(module: &Module, p: &Packet, m: usize) -> Option<Packet> {
    let member = &p.members[m];
    if !matches!(member.kind, MemberKind::Stored | MemberKind::BitfieldPart) || Some(m) == p.version_member {
        return None;
    }
    if matches!(member.ty, ValueType::Str | ValueType::Union(_)) {
        return None;
    }
    if !matches!(member.array, None | Some(Count::Expr(TExpr::IntLit(_)))) {
        return None;
    }
    if reads(p, m) {
        return None;
    }
    let targets = target_steps(p, m);
    let fixed = targets.iter().all(|&t| match &p.steps[t] {
        Step::Field { codec, .. } => module.elem_bits(codec).is_some(),
        Step::Bitfield { .. } => true,
        _ => false,
    });
    if targets.is_empty() || !fixed {
        return None;
    }

    let checksums = p.members.iter().any(|x| x.derived_expr().is_some_and(has_checksum));
    let cut = (!checksums && targets.len() == 1 && !in_window(p, targets[0]))
        .then(|| bits_mod8(module, &p.steps[..=targets[0]]))
        .flatten();
    let mut v = match cut {
        Some(_) => {
            let mut v = view(module, p, m, true)?;
            // The view drops checks: the new value must pass the member's own.
            if let Some(t) = v.members.iter().position(|x| x.name == member.name) {
                let mut checks = member.checks.clone();
                for c in &mut checks {
                    c.cond.visit_mut(&mut |e| match e {
                        TExpr::Ref { member, .. } | TExpr::Index { member, .. } | TExpr::Len { member }
                            if *member == m =>
                        {
                            *member = t
                        }
                        _ => {}
                    });
                }
                v.members[t].checks = checks;
                v.members[t].lenient = member.lenient;
            }
            v
        }
        None => whole(p)?,
    };
    v.name = setter_view_name(&p.name, &member.name);
    keep_raw(&mut v, member);
    if !v.open_ended {
        add_rest(&mut v, member, cut.unwrap_or(0));
    }
    v.open_ended = true;
    v.min_bits = 0;
    v.fixed_bits = None;
    v.alignment = 1;
    Some(v)
}

/// The whole packet, its end marks pinned to its last step so the `rest`
/// added after it does not count.
fn whole(p: &Packet) -> Option<Packet> {
    let last = p.steps.len().checked_sub(1)?;
    let mut v = p.clone();
    let end = |m: Mark| if m == Mark::PacketEnd { Mark::After(last) } else { m };
    for member in &mut v.members {
        if let MemberKind::Derived(e) | MemberKind::Calculated(e) = &mut member.kind {
            e.map_marks(&end);
        }
    }
    for a in &mut v.asserts {
        a.cond.map_marks(&end);
    }
    Some(v)
}

/// True if any expression of `p` other than `m`'s own checks reads `m`.
fn reads(p: &Packet, m: usize) -> bool {
    let mut exprs: Vec<&TExpr> = Vec::new();
    fn count<'a>(c: &'a Count, exprs: &mut Vec<&'a TExpr>) {
        if let Count::Expr(e) | Count::Until(e) = c {
            exprs.push(e);
        }
    }
    for step in &p.steps {
        match step {
            Step::Field { codec, array, .. } => {
                if let Some(c) = array {
                    count(c, &mut exprs);
                }
                if let Codec::Packet(r) = codec {
                    exprs.extend(&r.args);
                }
            }
            Step::Switch { selector, arms, .. } => {
                exprs.push(selector);
                for arm in arms {
                    if let Some(Codec::Packet(r)) = &arm.codec {
                        exprs.extend(&r.args);
                    }
                    if let Some(c) = &arm.count {
                        count(c, &mut exprs);
                    }
                }
            }
            Step::At { target, offset, .. } => {
                exprs.push(offset);
                exprs.extend(&target.args);
            }
            Step::OpenWindow { size, .. } => exprs.push(size),
            Step::OpenGate { cond, .. } => exprs.push(cond),
            _ => {}
        }
    }
    for (i, member) in p.members.iter().enumerate() {
        if let MemberKind::Derived(e) | MemberKind::Calculated(e) = &member.kind {
            exprs.push(e);
        }
        if let Some(c) = &member.array {
            count(c, &mut exprs);
        }
        exprs.extend(&member.present);
        if i != m {
            exprs.extend(member.checks.iter().map(|c| &c.cond));
        }
    }
    exprs.extend(p.asserts.iter().map(|a| &a.cond));
    exprs.iter().any(|e| {
        let mut out = Vec::new();
        e.deps(&mut out);
        out.contains(&m)
    })
}

fn has_checksum(e: &TExpr) -> bool {
    let mut out = Vec::new();
    e.checksums(&mut out);
    !out.is_empty()
}

/// True if step `at` is inside a `size n` window.
fn in_window(p: &Packet, at: usize) -> bool {
    let mut open = Vec::new();
    for (i, s) in p.steps[..at].iter().enumerate() {
        match s {
            Step::OpenWindow { .. } => open.push(i),
            Step::CloseWindow { open: o, .. } => open.retain(|x| x != o),
            _ => {}
        }
    }
    !open.is_empty()
}

/// The bit position modulo 8 after `steps` (from the start of the packet),
/// when it does not depend on the data.
fn bits_mod8(module: &Module, steps: &[Step]) -> Option<u64> {
    let codec_mod = |codec: &Codec, array: Option<&Count>| -> Option<u64> {
        let elem = match codec {
            Codec::Packet(_) | Codec::Varint(_) => return Some(0),
            Codec::Str(StrMode::Prefixed { prefix, .. }) => return Some(prefix.bits() as u64 % 8),
            Codec::Str(_) => return Some(0),
            c => module.elem_bits(c)?,
        };
        match array {
            None => Some(elem % 8),
            Some(_) if elem % 8 == 0 => Some(0),
            Some(Count::Expr(TExpr::IntLit(n))) => Some((elem * *n as u64) % 8),
            Some(_) => None,
        }
    };
    let mut pos = 0;
    let mut gates = Vec::new();
    for step in steps {
        pos = match step {
            Step::Field { codec, array, .. } => (pos + codec_mod(codec, array.as_ref())?) % 8,
            Step::Bitfield { container_width, .. } => (pos + *container_width as u64) % 8,
            Step::Switch { arms, .. } => {
                let all_bytes = arms.iter().all(|a| match &a.codec {
                    None => true,
                    Some(c) => codec_mod(c, a.count.as_ref()) == Some(0),
                });
                if !all_bytes {
                    return None;
                }
                pos
            }
            Step::Align { .. } | Step::CloseWindow { .. } => 0,
            Step::OpenGate { .. } => {
                gates.push(pos);
                pos
            }
            Step::CloseGate { .. } => {
                // A gate that may be skipped must not move the position.
                if gates.pop() != Some(pos) {
                    return None;
                }
                pos
            }
            _ => pos,
        };
    }
    Some(pos)
}

/// A hidden member named after `base`, unique in `v`.
fn hidden(v: &Packet, template: &Member, base: &str, ty: ValueType, array: Option<Count>, kind: MemberKind) -> Member {
    let mut name = base.to_string();
    let mut n = 1;
    while v.members.iter().any(|m| m.name.eq_ignore_ascii_case(&name)) {
        n += 1;
        name = format!("{}{}", base, n);
    }
    let mut m = template.clone();
    m.name = name;
    m.ty = ty;
    m.array = array;
    m.kind = kind;
    m.category = None;
    m.checks.clear();
    m.lenient = false;
    m.present = None;
    m
}

fn byte() -> (ValueType, Codec) {
    (ValueType::Int { width: 8, signed: false }, Codec::Bytes { nbytes: 1, endian: Endianness::Be })
}

/// `e / 8`, when `e` is visibly a multiple of 8.
fn div8(e: &TExpr) -> Option<TExpr> {
    match e {
        TExpr::IntLit(n) if n % 8 == 0 => Some(TExpr::IntLit(n / 8)),
        TExpr::Arith { op: ArithOp::Mul, a, b, ty } => match (&**a, &**b) {
            (_, TExpr::IntLit(k)) if k % 8 == 0 => Some(if *k == 8 {
                (**a).clone()
            } else {
                TExpr::Arith { op: ArithOp::Mul, a: a.clone(), b: Box::new(TExpr::IntLit(k / 8)), ty: *ty }
            }),
            _ => None,
        },
        TExpr::Arith { op: ArithOp::Add, a, b, ty } => {
            Some(TExpr::Arith { op: ArithOp::Add, a: Box::new(div8(a)?), b: Box::new(div8(b)?), ty: *ty })
        }
        _ => None,
    }
}

/// Turn padding (and skips) into hidden members, and add hidden parts for
/// the bits of bitfield containers no part covers, so encoding writes back
/// what was read.
fn keep_raw(v: &mut Packet, template: &Member) {
    for i in 0..v.steps.len() {
        match &v.steps[i] {
            Step::Field { member: None, ty, codec, array } => {
                let (ty, codec, array) = match (codec, array) {
                    (Codec::Bits { width: 1 }, Some(Count::Expr(e))) if div8(e).is_some() => {
                        let (t, c) = byte();
                        (t, c, Some(Count::Expr(div8(e).unwrap_or(TExpr::IntLit(0)))))
                    }
                    (Codec::Bits { width: 1 }, Some(Count::Expr(TExpr::IntLit(n)))) if (1..=64).contains(n) => {
                        let width = *n as u32;
                        (ValueType::Int { width, signed: false }, Codec::Bits { width }, None)
                    }
                    _ => (ty.clone(), codec.clone(), array.clone()),
                };
                let m = hidden(v, template, "skipped", ty.clone(), array.clone(), MemberKind::Stored);
                v.members.push(m);
                v.steps[i] = Step::Field { member: Some(v.members.len() - 1), ty, codec, array };
            }
            Step::Bitfield { container_width, parts, .. } => {
                let width = *container_width;
                let covered = |b: u32| parts.iter().any(|p| b >= p.shift && b < p.shift + p.width);
                let mut gaps = Vec::new();
                let mut b = 0;
                while b < width {
                    if covered(b) {
                        b += 1;
                        continue;
                    }
                    let lo = b;
                    while b < width && !covered(b) {
                        b += 1;
                    }
                    gaps.push((lo, b - lo));
                }
                for (shift, w) in gaps {
                    let ty = ValueType::Int { width: w, signed: false };
                    let m = hidden(v, template, "skipped", ty, None, MemberKind::BitfieldPart);
                    v.members.push(m);
                    let member = v.members.len() - 1;
                    if let Step::Bitfield { parts, .. } = &mut v.steps[i] {
                        parts.push(BitPart { member, shift, width: w, signed: false });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Add `rest`: everything after the view, kept as it is. `pos` is the bit
/// position modulo 8 where it starts.
fn add_rest(v: &mut Packet, template: &Member, pos: u64) {
    if pos != 0 {
        let width = (8 - pos) as u32;
        let ty = ValueType::Int { width, signed: false };
        let m = hidden(v, template, "skipped", ty.clone(), None, MemberKind::Stored);
        v.members.push(m);
        v.steps.push(Step::Field { member: Some(v.members.len() - 1), ty, codec: Codec::Bits { width }, array: None });
    }
    let (ty, codec) = byte();
    let m = hidden(v, template, "rest", ty.clone(), Some(Count::Remaining), MemberKind::Stored);
    v.members.push(m);
    v.steps.push(Step::Field { member: Some(v.members.len() - 1), ty, codec, array: Some(Count::Remaining) });
}
