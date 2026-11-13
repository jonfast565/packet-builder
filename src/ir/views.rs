//! Field views (`generate --access`): for every member of every packet, a
//! packet `<Packet>_<member>` that reads that member without decoding the
//! rest. Everything before the member that has a size known from values
//! already read is skipped; only the members the skips, windows and the
//! member itself depend on are read. Fields of a size known only by reading
//! them (strings, `until`, unions outside a `size n` window, ...) are read.
//!
//! Views are ordinary packets, so every backend decodes them as it decodes
//! any other: `Ipv4_ttl.decode(buf).ttl` reads one byte at offset 8.
//! They are decode-only: derived members are not verified, checks and
//! assertions are not enforced, and encoding a view writes zeros for the
//! skipped bits.

use std::collections::HashSet;

use super::expr::{ArithOp, TExpr, Ty};
use super::model::{Assertion, Codec, Count, Member, MemberKind, Module, Packet, Param, Step, ValueType};

impl Module {
    /// Add a view for every member of every packet. Fails if a view's name
    /// is already taken.
    pub fn add_views(&mut self) -> Result<(), String> {
        let mut views = Vec::new();
        let mut elements = Vec::new();
        for p in &self.packets {
            for m in 0..p.members.len() {
                if let Some(v) = view(self, p, m, false) {
                    elements.extend(element_view(self, &p.members[m].name, &v));
                    views.push(v);
                }
                elements.extend(super::setters::setter_view(self, p, m));
            }
        }
        let taken = |packets: &[Packet], name: &str| packets.iter().any(|p| p.name.eq_ignore_ascii_case(name));
        for (i, v) in views.iter().enumerate() {
            if taken(&self.packets, &v.name) || taken(&views[..i], &v.name) {
                return Err(format!("cannot add view `{}`: a packet has that name", v.name));
            }
        }
        // An element or setter view whose name is taken (a member
        // `<field>_at` or `<field>_set`) is left out: field views come first.
        for e in elements {
            if !taken(&self.packets, &e.name) && !taken(&views, &e.name) {
                views.push(e);
            }
        }
        self.packets.extend(views);
        Ok(())
    }

    /// Encoded size in bits of one element with `codec`, when it does not
    /// depend on the data.
    pub fn elem_bits(&self, codec: &Codec) -> Option<u64> {
        match codec {
            Codec::Bytes { .. } | Codec::Bits { .. } | Codec::Float { .. } | Codec::Mac => Some(codec.bits() as u64),
            Codec::Packet(r) => self.packets.iter().find(|p| p.name == r.name)?.fixed_bits,
            Codec::Str(super::model::StrMode::Padded | super::model::StrMode::Exact) => Some(8),
            Codec::Str(_) | Codec::Varint(_) => None,
        }
    }
}

/// The name of the view of member `member` of packet `packet`.
pub fn view_name(packet: &str, member: &str) -> String {
    format!("{}_{}", packet, member)
}

/// The name of the view of one element of array `member` of packet `packet`.
pub fn element_view_name(packet: &str, member: &str) -> String {
    format!("{}_{}_at", packet, member)
}

/// The parameter an element view takes: which element to read.
pub const INDEX_PARAM: &str = "index";

/// What the view does with a step of the original packet.
enum Plan {
    Keep,
    Drop,
    /// Skip this many bits: a constant plus expressions (in bits).
    Skip(u64, Vec<TExpr>),
}

fn int(v: i64) -> TExpr {
    TExpr::IntLit(v)
}

fn mul(a: TExpr, b: u64) -> TExpr {
    if b == 1 {
        return a;
    }
    TExpr::Arith { op: ArithOp::Mul, a: Box::new(a), b: Box::new(int(b as i64)), ty: Ty::Int }
}

fn add(a: TExpr, b: TExpr) -> TExpr {
    TExpr::Arith { op: ArithOp::Add, a: Box::new(a), b: Box::new(b), ty: Ty::Int }
}

fn deps(e: &TExpr, needed: &mut HashSet<usize>) {
    let mut out = Vec::new();
    e.deps(&mut out);
    needed.extend(out);
}

fn count_deps(c: &Count, needed: &mut HashSet<usize>) {
    match c {
        Count::Expr(e) | Count::Until(e) => deps(e, needed),
        Count::Remaining | Count::Terminated { .. } => {}
    }
}

fn codec_deps(c: &Codec, needed: &mut HashSet<usize>) {
    if let Codec::Packet(r) = c {
        r.args.iter().for_each(|a| deps(a, needed));
    }
}

/// The steps that hold member `m`.
pub(super) fn target_steps(p: &Packet, m: usize) -> Vec<usize> {
    let holds = |s: &Step| match s {
        Step::Field { member: Some(x), .. } | Step::Switch { member: x, .. } | Step::At { member: x, .. } => *x == m,
        Step::Calc { member } => *member == m,
        Step::Bitfield { parts, .. } => parts.iter().any(|b| b.member == m),
        _ => false,
    };
    p.steps.iter().enumerate().filter(|(_, s)| holds(s)).map(|(i, _)| i).collect()
}

/// `keep_parts`: keep every part of a bitfield the view reads (setter views
/// write the container back whole).
pub(super) fn view(module: &Module, p: &Packet, m: usize, keep_parts: bool) -> Option<Packet> {
    let targets = target_steps(p, m);
    let last = *targets.last()?;
    let mut needed: HashSet<usize> = HashSet::from([m]);
    needed.extend(p.version_member);
    let holds_needed = |s: &Step, needed: &HashSet<usize>| match s {
        Step::Field { member: Some(x), .. } | Step::Switch { member: x, .. } | Step::At { member: x, .. } => {
            needed.contains(x)
        }
        Step::Calc { member } => needed.contains(member),
        Step::Bitfield { parts, .. } => parts.iter().any(|b| needed.contains(&b.member)),
        _ => false,
    };

    let mut plan: Vec<Plan> = (0..=last).map(|_| Plan::Keep).collect();
    let mut i = last as isize;
    while i >= 0 {
        let at = i as usize;
        let step = &p.steps[at];
        let target = targets.contains(&at);
        match step {
            Step::Field { member, codec, array, .. } => {
                let keep = target || member.is_some_and(|x| needed.contains(&x));
                let size = module.elem_bits(codec).and_then(|e| match array {
                    None => Some((e, None)),
                    Some(Count::Expr(c)) => Some((0, Some(mul(c.clone(), e)))),
                    _ => None,
                });
                match size {
                    Some((bits, expr)) if !keep => {
                        if let Some(Count::Expr(c)) = array {
                            deps(c, &mut needed);
                        }
                        plan[at] = Plan::Skip(bits, expr.into_iter().collect());
                    }
                    _ => {
                        needed.extend(*member);
                        if let Some(c) = array {
                            count_deps(c, &mut needed);
                        }
                        codec_deps(codec, &mut needed);
                    }
                }
            }
            Step::Bitfield { container_width, parts, .. } => {
                if !target && !holds_needed(step, &needed) {
                    plan[at] = Plan::Skip(*container_width as u64, Vec::new());
                } else if keep_parts {
                    needed.extend(parts.iter().map(|b| b.member));
                }
            }
            Step::Calc { member } => {
                if target || needed.contains(member) {
                    deps(p.members[*member].calc_expr().expect("calculated member"), &mut needed);
                } else {
                    plan[at] = Plan::Drop;
                }
            }
            Step::Assert { .. } => plan[at] = Plan::Drop,
            Step::Switch { member, selector, arms } => {
                needed.insert(*member);
                deps(selector, &mut needed);
                for arm in arms {
                    if let Some(c) = &arm.codec {
                        codec_deps(c, &mut needed);
                    }
                    if let Some(c) = &arm.count {
                        count_deps(c, &mut needed);
                    }
                }
            }
            Step::At { member, target: r, offset, .. } => {
                if target || needed.contains(member) {
                    deps(offset, &mut needed);
                    r.args.iter().for_each(|a| deps(a, &mut needed));
                } else {
                    plan[at] = Plan::Drop;
                }
            }
            Step::CloseWindow { open, .. } => {
                // A window nothing inside is wanted from: skip all of it.
                let inside = *open + 1..at;
                let wanted = inside.clone().any(|j| targets.contains(&j) || holds_needed(&p.steps[j], &needed));
                if !wanted && let Step::OpenWindow { size, .. } = &p.steps[*open] {
                    deps(size, &mut needed);
                    for j in inside.clone() {
                        plan[j] = Plan::Drop;
                    }
                    plan[at] = Plan::Drop;
                    plan[*open] = Plan::Skip(0, vec![mul(size.clone(), 8)]);
                    i = *open as isize - 1;
                    continue;
                }
            }
            Step::OpenWindow { size, .. } => deps(size, &mut needed),
            Step::Align { .. } | Step::OpenGate { .. } | Step::CloseGate { .. } => {}
        }
        i -= 1;
    }

    // Members of the view, in their original order.
    let kept: Vec<usize> = (0..p.members.len()).filter(|x| needed.contains(x)).collect();
    let mut map = vec![usize::MAX; p.members.len()];
    for (new, &old) in kept.iter().enumerate() {
        map[old] = new;
    }
    let remap = |e: &mut TExpr| {
        e.visit_mut(&mut |x| match x {
            TExpr::Ref { member, .. }
            | TExpr::Index { member, .. }
            | TExpr::Aggregate { member, .. }
            | TExpr::Len { member }
            | TExpr::Stored { member } => *member = map[*member],
            _ => {}
        })
    };

    let mut steps: Vec<Step> = Vec::new();
    let mut step_map = vec![usize::MAX; p.steps.len()];
    let mut skip: Option<(u64, Vec<TExpr>)> = None;
    let flush = |steps: &mut Vec<Step>, skip: &mut Option<(u64, Vec<TExpr>)>| {
        let Some((bits, exprs)) = skip.take() else { return };
        let mut count: Option<TExpr> = (bits > 0).then(|| int(bits as i64));
        for e in exprs {
            count = Some(match count {
                Some(c) => add(c, e),
                None => e,
            });
        }
        let Some(count) = count else { return };
        steps.push(Step::Field {
            member: None,
            ty: ValueType::Int { width: 1, signed: false },
            codec: Codec::Bits { width: 1 },
            array: Some(Count::Expr(count)),
        });
    };
    let mut open: Vec<(bool, usize)> = Vec::new(); // (is a window, old index) still open at the cut
    for (at, step_plan) in plan.into_iter().enumerate() {
        match step_plan {
            Plan::Drop => continue,
            Plan::Skip(bits, exprs) => {
                let s = skip.get_or_insert((0, Vec::new()));
                s.0 += bits;
                for mut e in exprs {
                    remap(&mut e);
                    s.1.push(e);
                }
                continue;
            }
            Plan::Keep => {}
        }
        flush(&mut steps, &mut skip);
        let mut step = p.steps[at].clone();
        match &mut step {
            Step::Field { member, codec, array, .. } => {
                *member = member.map(|x| map[x]);
                if let Some(Count::Expr(e) | Count::Until(e)) = array {
                    remap(e);
                }
                if let Codec::Packet(r) = codec {
                    r.args.iter_mut().for_each(remap);
                }
            }
            Step::Bitfield { parts, .. } => {
                parts.retain(|b| map[b.member] != usize::MAX);
                parts.iter_mut().for_each(|b| b.member = map[b.member]);
            }
            Step::Calc { member } => *member = map[*member],
            Step::Switch { member, selector, arms } => {
                *member = map[*member];
                remap(selector);
                for arm in arms {
                    if let Some(Codec::Packet(r)) = &mut arm.codec {
                        r.args.iter_mut().for_each(remap);
                    }
                    if let Some(Count::Expr(e) | Count::Until(e)) = &mut arm.count {
                        remap(e);
                    }
                }
            }
            Step::At { member, target, offset, .. } => {
                *member = map[*member];
                remap(offset);
                target.args.iter_mut().for_each(remap);
            }
            Step::OpenWindow { size, .. } => {
                remap(size);
                open.push((true, at));
            }
            Step::OpenGate { .. } => open.push((false, at)),
            Step::CloseWindow { open: o, .. } | Step::CloseGate { open: o } => {
                open.retain(|(_, x)| x != o);
                *o = step_map[*o];
            }
            Step::Align { .. } | Step::Assert { .. } => {}
        }
        step_map[at] = steps.len();
        steps.push(step);
    }
    flush(&mut steps, &mut skip);
    // Close what is still open at the cut, innermost first.
    for (window, o) in open.into_iter().rev() {
        steps.push(if window {
            Step::CloseWindow { open: step_map[o], exact: false }
        } else {
            Step::CloseGate { open: step_map[o] }
        });
    }

    let members: Vec<Member> = kept
        .iter()
        .map(|&old| {
            let mut member = p.members[old].clone();
            member.checks.clear();
            member.lenient = false;
            member.kind = match member.kind {
                // The version member stays derived: decoding adopts its value
                // as the version, encoding writes the writer's.
                MemberKind::Derived(e) if Some(old) == p.version_member => MemberKind::Derived(e),
                MemberKind::Derived(_) => MemberKind::Stored,
                MemberKind::Calculated(mut e) => {
                    remap(&mut e);
                    MemberKind::Calculated(e)
                }
                k => k,
            };
            if let Some(e) = &mut member.present {
                remap(e);
            }
            member
        })
        .collect();
    // The members the view's own expressions read.
    let mut read = HashSet::new();
    for step in &steps {
        match step {
            Step::Field { codec, array, .. } => {
                if let Some(c) = array {
                    count_deps(c, &mut read);
                }
                codec_deps(codec, &mut read);
            }
            Step::Switch { selector, arms, .. } => {
                deps(selector, &mut read);
                for arm in arms {
                    if let Some(c) = &arm.codec {
                        codec_deps(c, &mut read);
                    }
                    if let Some(c) = &arm.count {
                        count_deps(c, &mut read);
                    }
                }
            }
            Step::At { target, offset, .. } => {
                deps(offset, &mut read);
                target.args.iter().for_each(|a| deps(a, &mut read));
            }
            Step::OpenWindow { size, .. } => deps(size, &mut read),
            _ => {}
        }
    }
    for member in &members {
        if let Some(e) = member.calc_expr() {
            deps(e, &mut read);
        }
    }

    Some(Packet {
        name: view_name(&p.name, &p.members[m].name),
        params: p.params.clone(),
        members,
        steps,
        // Derived members are plain in a view, and a calculated one is only
        // evaluated when encoding needs it (for a count or a size).
        encode_calcs: p
            .encode_calcs
            .iter()
            .filter(|&&c| map[c] != usize::MAX)
            .filter(|&&c| Some(c) == p.version_member || p.members[c].is_calculated() && read.contains(&map[c]))
            .map(|&c| map[c])
            .collect(),
        min_bits: 0,
        open_ended: false,
        fixed_bits: None,
        alignment: 1,
        asserts: Vec::new(),
        derived: p.version_member.filter(|v| p.derived.contains(v)).map(|v| map[v]).into_iter().collect(),
        patches: Vec::new(),
        wire_dependent: Vec::new(),
        version_member: p.version_member.map(|v| map[v]),
        versions: p.versions,
    })
}

/// From the view `v` of array member `name`, a view of element `index` of
/// it (a parameter): `<Packet>_<field>_at`. Elements of a fixed size are
/// skipped; others are read into `<field>_before`. Arrays read with
/// `until` or `term`, and strings, have none. An index past a counted
/// array's end is a `constraint` error.
fn element_view(module: &Module, name: &str, v: &Packet) -> Option<Packet> {
    let target = v.members.iter().position(|m| m.name == name)?;
    let member = &v.members[target];
    if member.ty == ValueType::Str || !matches!(member.array, Some(Count::Expr(_) | Count::Remaining)) {
        return None;
    }
    // Only arrays read in place (not through `at`), and only one index.
    let in_place =
        v.steps.iter().any(|s| matches!(s, Step::Field { member: Some(m), array: Some(_), .. } if *m == target));
    if !in_place || v.params.iter().any(|p| p.name == INDEX_PARAM) {
        return None;
    }
    let packet = v.name.strip_suffix(&format!("_{}", name))?;
    let mut e = v.clone();
    e.name = element_view_name(packet, name);
    let index = TExpr::Param { index: e.params.len() };
    e.params.push(Param { name: INDEX_PARAM.into(), ty: ValueType::Int { width: 32, signed: false } });
    e.members[target].array = None;
    let before = e.members.len();
    let mut before_member = member.clone();
    before_member.name = format!("{}_before", name);
    before_member.array = Some(Count::Expr(index.clone()));
    let mut uses_before = false;

    let mut steps = Vec::with_capacity(e.steps.len() + 2);
    let mut map = Vec::with_capacity(e.steps.len());
    for step in e.steps.drain(..) {
        let Step::Field { member: Some(m), ty, codec, array: Some(count) } = step else {
            map.push(steps.len());
            steps.push(step);
            continue;
        };
        if m != target {
            map.push(steps.len());
            steps.push(Step::Field { member: Some(m), ty, codec, array: Some(count) });
            continue;
        }
        if let Count::Expr(n) = &count {
            e.asserts.push(Assertion {
                cond: TExpr::Cmp { op: super::expr::CmpOp::Lt, a: Box::new(index.clone()), b: Box::new(n.clone()) },
                message: format!("`{}` must be less than the number of elements of `{}`", INDEX_PARAM, name),
            });
            steps.push(Step::Assert { index: e.asserts.len() - 1 });
        }
        match module.elem_bits(&codec) {
            Some(bits) => steps.push(Step::Field {
                member: None,
                ty: ValueType::Int { width: 1, signed: false },
                codec: Codec::Bits { width: 1 },
                array: Some(Count::Expr(mul(index.clone(), bits))),
            }),
            // `<field>_before` must not clash with a member the view keeps.
            None if e.members.iter().any(|m| m.name == before_member.name) => return None,
            None => {
                uses_before = true;
                steps.push(Step::Field {
                    member: Some(before),
                    ty: ty.clone(),
                    codec: codec.clone(),
                    array: Some(Count::Expr(index.clone())),
                });
            }
        }
        map.push(steps.len());
        steps.push(Step::Field { member: Some(m), ty, codec, array: None });
    }
    for step in &mut steps {
        if let Step::CloseWindow { open, .. } | Step::CloseGate { open } = step {
            *open = map[*open];
        }
    }
    e.steps = steps;
    if uses_before {
        e.members.push(before_member);
    }
    Some(e)
}
