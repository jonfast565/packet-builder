//! Frame lengths: when a packet's total size follows from a few header
//! fields at fixed offsets (FLAP: 6 header bytes plus `length`), a reader of
//! a byte stream can tell how many bytes one packet takes after reading only
//! the header. Wireshark's TCP reassembly and the streaming decoders use it.

use super::expr::{ArithOp, CmpOp, LogicOp, TExpr, Ty};
use super::model::{Module, Packet};
use super::wire::{Codec, Count, Step};

/// A header value the frame length depends on: `bits` bits at `shift` in
/// the `container_bits`-bit integer at `offset_bits` (shift 0 and the full
/// width for plain fields).
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderField {
    pub member: usize,
    pub offset_bits: u64,
    pub container: Codec,
    pub container_bits: u32,
    pub shift: u32,
    pub bits: u32,
    pub signed: bool,
    /// Read only when this holds (an expression over the version field read
    /// before it): a field that is elsewhere in other protocol versions.
    pub when: Option<TExpr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameLength {
    /// Bytes needed before the length is known.
    pub header_bytes: u64,
    /// The header fields `total` may read, at fixed positions.
    pub fields: Vec<HeaderField>,
    /// Calculated members of the header, evaluated in order before `total`.
    pub calcs: Vec<usize>,
    /// The packet's size in bytes, an expression over those members.
    pub total: TExpr,
    /// When the header's size depends on the protocol version: its size, an
    /// expression over the version field (`fields[0]`, within
    /// `header_bytes`), checked before the other fields are read.
    pub version_header: Option<TExpr>,
}

fn add(a: TExpr, b: TExpr) -> TExpr {
    TExpr::Arith { op: ArithOp::Add, a: Box::new(a), b: Box::new(b), ty: Ty::Int }
}

/// `e` with sums of two literals added up (keeps per-version lengths short).
fn fold(e: TExpr) -> TExpr {
    match e {
        TExpr::Arith { op: ArithOp::Add, a, b, ty: Ty::Int } => match (fold(*a), fold(*b)) {
            (TExpr::IntLit(x), TExpr::IntLit(y)) => TExpr::IntLit(x.wrapping_add(y)),
            (a, b) => TExpr::Arith { op: ArithOp::Add, a: Box::new(a), b: Box::new(b), ty: Ty::Int },
        },
        e => e,
    }
}

fn mul(a: TExpr, b: TExpr) -> TExpr {
    TExpr::Arith { op: ArithOp::Mul, a: Box::new(a), b: Box::new(b), ty: Ty::Int }
}

impl Module {
    /// How to find the size of `p` from its header, if it has a fixed-size
    /// header followed by at most one part whose size is a header expression
    /// (a `size n` window or an array `[n]` of fixed-size elements), then a
    /// fixed-size tail.
    ///
    /// A packet with fields for some protocol versions only has a frame
    /// length when every version's can be found from the header: the same in
    /// every version, or chosen by the version field (`ver uint8 = version`).
    pub fn frame_length(&self, p: &Packet) -> Option<FrameLength> {
        let gated = p.steps.iter().any(|s| matches!(s, Step::OpenGate { .. }));
        if !gated {
            return self.frame_length_of(p, &(0..p.steps.len()).collect::<Vec<_>>());
        }
        let (min, latest) = p.version_bounds();
        let mut each: Vec<(u32, FrameLength)> = Vec::new();
        for v in min..=latest {
            each.push((v, self.frame_length_of(p, &steps_in(p, v))?));
        }
        if each.windows(2).all(|w| w[0].1 == w[1].1) {
            return each.pop().map(|(_, f)| f);
        }
        per_version(p, each, min, latest)
    }

    fn frame_length_of(&self, p: &Packet, order: &[usize]) -> Option<FrameLength> {
        let fixed = |codec: &Codec| -> Option<u64> {
            match codec {
                Codec::Bytes { .. } | Codec::Bits { .. } | Codec::Float { .. } | Codec::Mac => {
                    Some(codec.bits() as u64)
                }
                Codec::Packet(r) => {
                    let nested = self.packets.iter().find(|x| x.name == r.name)?;
                    nested.fixed_bits
                }
                _ => None,
            }
        };
        let mut offset = 0u64;
        let mut fields = Vec::new();
        let mut calcs = Vec::new();
        let mut known: Vec<usize> = Vec::new();
        // The variable part: (bits before it, its size in bytes).
        let mut variable: Option<(u64, TExpr)> = None;
        let mut tail = 0u64;
        let uses_known = |e: &TExpr, known: &[usize]| {
            let mut deps = Vec::new();
            e.deps(&mut deps);
            deps.iter().all(|d| known.contains(d))
        };
        let mut k = 0;
        while k < order.len() {
            let i = order[k];
            let step = &p.steps[i];
            let grow = |n: u64, offset: &mut u64, tail: &mut u64, variable: &Option<(u64, TExpr)>| {
                if variable.is_some() { *tail += n } else { *offset += n }
            };
            match step {
                Step::Calc { member } => {
                    if variable.is_none()
                        && let Some(e) = p.members[*member].calc_expr()
                        && uses_known(e, &known)
                    {
                        calcs.push(*member);
                        known.push(*member);
                    }
                }
                Step::Assert { .. } | Step::At { .. } => {}
                Step::Align { bytes } => {
                    let unit = bytes * 8;
                    let pos = if variable.is_some() { None } else { Some(offset) };
                    let pad = (unit - pos? % unit) % unit;
                    grow(pad, &mut offset, &mut tail, &variable);
                }
                Step::Field { member, codec, array: None, ty } => {
                    let bits = fixed(codec)?;
                    if let (Some(m), None, Codec::Bytes { .. } | Codec::Bits { .. }) = (member, &variable, codec)
                        && matches!(ty, super::model::ValueType::Int { .. })
                    {
                        fields.push(HeaderField {
                            member: *m,
                            offset_bits: offset,
                            container: codec.clone(),
                            container_bits: bits as u32,
                            shift: 0,
                            bits: bits as u32,
                            signed: ty.is_signed(),
                            when: None,
                        });
                        known.push(*m);
                    }
                    grow(bits, &mut offset, &mut tail, &variable);
                }
                Step::Bitfield { container, container_width, parts, .. } => {
                    if variable.is_none() {
                        for part in parts {
                            fields.push(HeaderField {
                                member: part.member,
                                offset_bits: offset,
                                container: container.clone(),
                                container_bits: *container_width,
                                shift: part.shift,
                                bits: part.width,
                                signed: part.signed,
                                when: None,
                            });
                            known.push(part.member);
                        }
                    }
                    grow(*container_width as u64, &mut offset, &mut tail, &variable);
                }
                Step::Field { codec, array: Some(Count::Expr(e)), .. } => {
                    let elem = fixed(codec)?;
                    if variable.is_some() || !uses_known(e, &known) || !elem.is_multiple_of(8) {
                        return None;
                    }
                    variable = Some((offset, mul(e.clone(), TExpr::IntLit((elem / 8) as i64))));
                }
                Step::OpenWindow { size, .. } => {
                    if variable.is_some() || !uses_known(size, &known) {
                        return None;
                    }
                    variable = Some((offset, size.clone()));
                    // Whatever is inside takes exactly the window.
                    k = order
                        .iter()
                        .position(|&s| matches!(p.steps[s], Step::CloseWindow { open, .. } if open == i))?;
                }
                _ => return None,
            }
            k += 1;
        }
        let (start, size) = variable.unwrap_or((offset, TExpr::IntLit(0)));
        if !start.is_multiple_of(8) || !tail.is_multiple_of(8) || p.open_ended {
            return None;
        }
        let header_bytes = start / 8;
        let total = add(TExpr::IntLit((header_bytes + tail / 8) as i64), size);
        // Keep only what the total reads, directly or through calculated members.
        let mut needed = Vec::new();
        total.deps(&mut needed);
        for &c in calcs.iter().rev() {
            if needed.contains(&c)
                && let Some(e) = p.members[c].calc_expr()
            {
                e.deps(&mut needed);
            }
        }
        fields.retain(|h| needed.contains(&h.member));
        calcs.retain(|c| needed.contains(c));
        Some(FrameLength { header_bytes, fields, calcs, total, version_header: None })
    }
}

/// The steps of `p` in protocol version `v`, gates resolved.
fn steps_in(p: &Packet, v: u32) -> Vec<usize> {
    let mut out = Vec::new();
    let mut skip = false;
    for (i, s) in p.steps.iter().enumerate() {
        match s {
            Step::OpenGate { from, to, .. } => skip = !(*from..=*to).contains(&v),
            Step::CloseGate { .. } => skip = false,
            _ if !skip => out.push(i),
            _ => {}
        }
    }
    out
}

/// One frame length from each version's, chosen by the version field read
/// from the header. A header field the lengths read must be in the same
/// place in every version that reads it.
fn per_version(p: &Packet, each: Vec<(u32, FrameLength)>, min: u32, latest: u32) -> Option<FrameLength> {
    let vm = p.version_member?;
    let version = TExpr::Ref { member: vm, ty: Ty::Int };
    let cmp = |op, x: u32| TExpr::Cmp { op, a: Box::new(version.clone()), b: Box::new(TExpr::IntLit(x as i64)) };
    // The test for versions from..=to, over the version field.
    let test = |from: u32, to: u32| {
        let lo = (from > min).then(|| cmp(CmpOp::Gte, from));
        let hi = (to < latest).then(|| cmp(CmpOp::Lte, to));
        match (lo, hi) {
            (Some(a), Some(b)) => Some(TExpr::Logic { op: LogicOp::And, a: Box::new(a), b: Box::new(b) }),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    };
    // Each distinct header field, with the versions that read it.
    let mut found: Vec<(HeaderField, Vec<u32>)> = Vec::new();
    let mut calcs: Vec<usize> = Vec::new();
    for (v, f) in &each {
        for h in &f.fields {
            match found.iter_mut().find(|(x, _)| x == h) {
                Some((_, vs)) => vs.push(*v),
                None => found.push((h.clone(), vec![*v])),
            }
        }
        for &c in &f.calcs {
            // Calculated members are evaluated without a reader.
            if p.members[c].calc_expr().is_some_and(uses_version) {
                return None;
            }
            if !calcs.contains(&c) {
                calcs.push(c);
            }
        }
    }
    let mut fields: Vec<HeaderField> = Vec::new();
    // The version field first: the others may depend on it.
    let vfield = match found.iter().position(|(h, _)| h.member == vm) {
        Some(i) => found.remove(i).0,
        None => version_field(p, vm)?,
    };
    // The version field first; then the header size of its version.
    let header_bytes = (vfield.offset_bits + vfield.container_bits as u64).div_ceil(8);
    let mut sizes: Vec<(u32, u32, u64)> = Vec::new();
    for (v, f) in &each {
        let n = f.header_bytes.max(header_bytes);
        match sizes.last_mut() {
            Some((_, to, m)) if *m == n => *to = *v,
            _ => sizes.push((*v, *v, n)),
        }
    }
    let version_header = if sizes.len() == 1 && sizes[0].2 == header_bytes {
        None
    } else {
        let (last, rest) = sizes.split_last()?;
        Some(rest.iter().rev().fold(TExpr::IntLit(last.2 as i64), |other, (from, to, n)| TExpr::Guard {
            cond: Box::new(test(*from, *to).unwrap_or_else(|| cmp(CmpOp::Gte, 0))),
            then: Box::new(TExpr::IntLit(*n as i64)),
            other: Box::new(other),
            ty: Ty::Int,
        }))
    };
    fields.push(vfield);
    for (mut h, vs) in found {
        // Runs of consecutive versions; a field read in all of them needs no test.
        let mut runs: Vec<(u32, u32)> = Vec::new();
        for v in vs {
            match runs.last_mut() {
                Some((_, to)) if *to + 1 == v => *to = v,
                _ => runs.push((v, v)),
            }
        }
        h.when = runs.iter().map(|&(f, t)| test(f, t)).collect::<Option<Vec<_>>>().and_then(|ts| {
            ts.into_iter().reduce(|a, b| TExpr::Logic { op: LogicOp::Or, a: Box::new(a), b: Box::new(b) })
        });
        fields.push(h);
    }
    // Runs of versions with the same total.
    let mut runs: Vec<(u32, u32, TExpr)> = Vec::new();
    for (v, f) in each {
        let total = fold(f.total);
        match runs.last_mut() {
            Some((_, to, t)) if *t == total => *to = v,
            _ => runs.push((v, v, total)),
        }
    }
    let (last, rest) = runs.split_last()?;
    let total = rest.iter().rev().fold(last.2.clone(), |other, (from, to, t)| {
        let cond = test(*from, *to).unwrap_or_else(|| cmp(CmpOp::Gte, 0));
        TExpr::Guard { cond: Box::new(cond), then: Box::new(t.clone()), other: Box::new(other), ty: Ty::Int }
    });
    if uses_version(&total) {
        return None;
    }
    Some(FrameLength { header_bytes, fields, calcs, total, version_header })
}

fn uses_version(e: &TExpr) -> bool {
    let mut found = false;
    let mut e = e.clone();
    e.visit_mut(&mut |x| found |= matches!(x, TExpr::Version));
    found
}

/// Where the version field is: at a fixed offset, before any gate.
fn version_field(p: &Packet, member: usize) -> Option<HeaderField> {
    let mut offset = 0u64;
    for s in &p.steps {
        match s {
            Step::Field { member: m, codec: codec @ (Codec::Bytes { .. } | Codec::Bits { .. }), array: None, ty } => {
                let bits = codec.bits();
                if *m == Some(member) {
                    return Some(HeaderField {
                        member,
                        offset_bits: offset,
                        container: codec.clone(),
                        container_bits: bits,
                        shift: 0,
                        bits,
                        signed: ty.is_signed(),
                        when: None,
                    });
                }
                offset += bits as u64;
            }
            Step::Calc { .. } | Step::Assert { .. } => {}
            _ => return None,
        }
    }
    None
}
