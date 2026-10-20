//! `packet_builder diff`: what changed on the wire between two versions of a
//! description. Changes that make old and new peers disagree about bytes
//! are incompatible: removed, added, moved or resized fields, a changed type
//! or byte order, changed constant or category values, removed union arms.
//! New packets, new union arms and new category members are compatible.

use crate::ast::Endianness;
use crate::ir::{Codec, Count, Module, Packet, Step, StrMode, Union};

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub compatible: bool,
    pub message: String,
}

fn incompatible(message: String) -> Change {
    Change { compatible: false, message }
}

fn compatible(message: String) -> Change {
    Change { compatible: true, message }
}

fn endian(e: &Endianness) -> &'static str {
    if *e == Endianness::Le { "little-endian" } else { "big-endian" }
}

/// How a value travels, in words.
fn codec(c: &Codec) -> String {
    match c {
        Codec::Bytes { nbytes: 1, .. } => "1 byte".into(),
        Codec::Bytes { nbytes, endian: e } => format!("{} bytes {}", nbytes, endian(e)),
        Codec::Bits { width } => format!("{} bits", width),
        Codec::Float { width, endian: e } => format!("{}-bit float {}", width, endian(e)),
        Codec::Mac => "mac address".into(),
        Codec::Packet(r) => format!("packet {}", r.name),
        Codec::Varint(k) => k.name().into(),
        Codec::Str(StrMode::Padded) => "padded text".into(),
        Codec::Str(StrMode::Exact) => "text".into(),
        Codec::Str(StrMode::CString) => "NUL-terminated text".into(),
        Codec::Str(StrMode::Prefixed { prefix, .. }) => format!("text with a {} length", codec(prefix)),
        Codec::Str(StrMode::Terminated { term, .. }) => format!("text ending in {:02x?}", term),
    }
}

fn count(c: &Option<Count>) -> &'static str {
    match c {
        None => "",
        Some(Count::Expr(_)) => " array",
        Some(Count::Remaining) => " array to the end",
        Some(Count::Until(_)) => " array until a condition",
        Some(Count::Terminated { .. }) => " ending in a terminator",
    }
}

/// The wire fields of a packet, in order: (name, description).
fn fields(p: &Packet) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for s in &p.steps {
        match s {
            Step::Field { member, codec: c, array, .. } => {
                let name = member.map(|m| p.members[m].name.clone()).unwrap_or_else(|| "_".into());
                out.push((name, format!("{}{}", codec(c), count(array))));
            }
            Step::Bitfield { parts, container, .. } => {
                for part in parts {
                    let at = format!("bits {}..{} of {}", part.shift, part.shift + part.width - 1, codec(container));
                    out.push((p.members[part.member].name.clone(), at));
                }
            }
            Step::Switch { member, .. } => out.push((p.members[*member].name.clone(), "union".into())),
            Step::At { member, target, root, .. } => out.push((
                p.members[*member].name.clone(),
                format!("packet {} at {}an offset", target.name, if *root { "root " } else { "" }),
            )),
            Step::Align { bytes } => out.push(("_".into(), format!("padding to {} bytes", bytes))),
            Step::OpenWindow { exact, .. } => {
                out.push(("(size)".into(), format!("window{}", if *exact { " exact" } else { "" })))
            }
            _ => {}
        }
    }
    out
}

fn packet(old: &Packet, new: &Packet, out: &mut Vec<Change>) {
    let (a, b) = (fields(old), fields(new));
    let name = &old.name;
    let names = |v: &[(String, String)]| v.iter().map(|f| f.0.clone()).collect::<Vec<_>>();
    let (an, bn) = (names(&a), names(&b));
    for (i, (f, desc)) in a.iter().enumerate() {
        if f == "_" || f == "(size)" {
            continue;
        }
        match b.iter().position(|(g, _)| g == f) {
            None => out.push(incompatible(format!("{}: field `{}` was removed", name, f))),
            Some(j) => {
                // Moved: the fields before it differ.
                let before_a: Vec<&String> = an[..i].iter().filter(|x| bn.contains(x)).collect();
                let before_b: Vec<&String> = bn[..j].iter().filter(|x| an.contains(x)).collect();
                if before_a != before_b {
                    out.push(incompatible(format!("{}: field `{}` moved", name, f)));
                }
                if &b[j].1 != desc {
                    out.push(incompatible(format!("{}: field `{}` changed from {} to {}", name, f, desc, b[j].1)));
                }
            }
        }
    }
    for (f, desc) in &b {
        if f != "_" && f != "(size)" && !an.contains(f) {
            out.push(incompatible(format!("{}: field `{}` ({}) was added", name, f, desc)));
        }
    }
    let pad = |v: &[(String, String)]| v.iter().filter(|f| f.0 == "_" || f.0 == "(size)").cloned().collect::<Vec<_>>();
    if pad(&a) != pad(&b) {
        out.push(incompatible(format!("{}: padding, alignment or sizes changed", name)));
    }
    if old.fixed_bits != new.fixed_bits && old.fixed_bits.is_some() && new.fixed_bits.is_some() {
        out.push(incompatible(format!(
            "{}: size changed from {} to {} bits",
            name,
            old.fixed_bits.unwrap_or(0),
            new.fixed_bits.unwrap_or(0)
        )));
    }
}

fn union(old: &Union, new: &Union, out: &mut Vec<Change>) {
    for arm in &old.arms {
        match new.arms.iter().find(|a| a.name == arm.name) {
            None => out.push(incompatible(format!("{}: arm `{}` was removed", old.name, arm.name))),
            Some(n) if n.values != arm.values || n.default != arm.default => out.push(incompatible(format!(
                "{}: arm `{}` is now picked by {:?} instead of {:?}",
                old.name, arm.name, n.values, arm.values
            ))),
            Some(_) => {}
        }
    }
    for arm in new.arms.iter().filter(|a| !old.arms.iter().any(|o| o.name == a.name)) {
        out.push(compatible(format!("{}: new arm `{}` for {:?}", old.name, arm.name, arm.values)));
    }
}

/// Every wire-relevant change from `old` to `new`.
pub fn diff(old: &Module, new: &Module) -> Vec<Change> {
    let mut out = Vec::new();
    for p in &old.packets {
        match new.packets.iter().find(|n| n.name == p.name) {
            None => out.push(incompatible(format!("packet `{}` was removed", p.name))),
            Some(n) => packet(p, n, &mut out),
        }
    }
    for p in new.packets.iter().filter(|n| !old.packets.iter().any(|o| o.name == n.name)) {
        out.push(compatible(format!("new packet `{}`", p.name)));
    }
    for u in &old.unions {
        if let Some(n) = new.unions.iter().find(|n| n.name == u.name) {
            union(u, n, &mut out);
        }
    }
    for c in &old.constants {
        match new.constants.iter().find(|n| n.name == c.name) {
            Some(n) if n.value != c.value => {
                out.push(incompatible(format!("constant `{}` changed from {} to {}", c.name, c.literal(), n.literal())))
            }
            None => out.push(compatible(format!("constant `{}` was removed", c.name))),
            _ => {}
        }
    }
    for cat in &old.categories {
        let Some(n) = new.categories.iter().find(|n| n.name == cat.name) else {
            out.push(compatible(format!("category `{}` was removed", cat.name)));
            continue;
        };
        for c in &cat.members {
            match n.members.iter().find(|m| m.name == c.name) {
                None => out.push(incompatible(format!("{}.{} was removed", cat.name, c.name))),
                Some(m) if m.value != c.value => out.push(incompatible(format!(
                    "{}.{} changed from {} to {}",
                    cat.name,
                    c.name,
                    c.literal(),
                    m.literal()
                ))),
                _ => {}
            }
        }
        for m in n.members.iter().filter(|m| !cat.members.iter().any(|c| c.name == m.name)) {
            out.push(compatible(format!("new {}.{} = {}", cat.name, m.name, m.literal())));
        }
    }
    out
}
