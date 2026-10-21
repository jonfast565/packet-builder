//! Field-by-field layout report (the `layout` command).

use super::model::{CheckKind, Codec, Count, Member, Module, Packet, Step, StrMode, TextEncoding, ValueType};

/// ` term 0x0d 0x0a optional`
fn term_suffix(term: &[u8], optional: bool) -> String {
    let t: Vec<String> = term.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!(" term {}{}", t.join(" "), if optional { " optional" } else { "" })
}

/// `u8` becomes `u8 : Channel strict == 0x2a lenient` with the member's
/// category and checks.
fn with_category(kind: String, member: Option<&Member>) -> String {
    let Some(m) = member else { return kind };
    let mut out = kind;
    if let Some(c) = &m.category {
        out = format!("{} : {}", out, c);
    }
    for check in &m.checks {
        match &check.kind {
            CheckKind::InCategory(_) => out.push_str(" strict"),
            CheckKind::Equals(v) if *v >= 10 => out.push_str(&format!(" == 0x{:x}", v)),
            CheckKind::Equals(v) => out.push_str(&format!(" == {}", v)),
            CheckKind::Range(lo, hi) => out.push_str(&format!(" in {}..{}", lo, hi)),
        }
    }
    if let Some(p) = m.placeholder() {
        out.push_str(&format!(" (derived, placeholder {:#x})", p));
    } else if m.is_derived() {
        out.push_str(" (derived)");
    }
    if m.lenient {
        out.push_str(" lenient");
    }
    out
}

/// One row of a packet's layout, for display.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutRow {
    /// Bit offset from the packet start, when it does not depend on the data.
    pub offset_bits: Option<u64>,
    /// Size in bits, when it does not depend on the data.
    pub size_bits: Option<u64>,
    /// Member name, `_` for padding, or the name of a bitfield member.
    pub name: String,
    pub kind: String,
    /// Indented under the previous row (bitfield members).
    pub nested: bool,
}

impl Module {
    /// Field-by-field layout of `packet`, including padding inserted by alignment.
    pub fn layout(&self, packet: &Packet) -> Vec<LayoutRow> {
        self.layout_version(packet, None)
    }

    /// The layout of `packet` in protocol `version`; with None, fields that
    /// exist in some versions only are listed under the versions they
    /// exist in.
    pub fn layout_version(&self, packet: &Packet, version: Option<u32>) -> Vec<LayoutRow> {
        let mut rows = Vec::new();
        let mut offset = Some(0u64);
        // An open window: where it starts and its size.
        let mut window: Option<(Option<u64>, Option<u64>)> = None;
        // Inside a gate: skipping it (another version), or listing it.
        let mut skipping = false;
        let mut in_gate = false;
        for step in &packet.steps {
            if skipping && !matches!(step, Step::CloseGate { .. }) {
                continue;
            }
            match step {
                Step::Calc { .. } | Step::Assert { .. } => {}
                Step::OpenGate { from, to, .. } => {
                    match version {
                        Some(v) => skipping = !(*from..=*to).contains(&v),
                        None => {
                            let name = if from == to {
                                format!("(version {})", from)
                            } else {
                                format!("(versions {}..{})", from, to)
                            };
                            rows.push(LayoutRow {
                                offset_bits: offset,
                                size_bits: None,
                                name,
                                kind: "the next fields exist in these versions only".into(),
                                nested: false,
                            });
                            in_gate = true;
                        }
                    }
                    continue;
                }
                Step::CloseGate { .. } => {
                    if in_gate {
                        // Skipped in the other versions: the size is not known.
                        offset = None;
                    }
                    skipping = false;
                    in_gate = false;
                    continue;
                }
                Step::OpenWindow { size, exact } => {
                    let bits = size.const_int().map(|n| n.max(0) as u64 * 8);
                    rows.push(LayoutRow {
                        offset_bits: offset,
                        size_bits: bits,
                        name: "(window)".into(),
                        kind: if *exact {
                            "the next field fills exactly".into()
                        } else {
                            "the next field, then padding".into()
                        },
                        nested: false,
                    });
                    window = Some((offset, bits));
                    continue;
                }
                Step::CloseWindow { .. } => {
                    if let Some((start, bits)) = window.take() {
                        offset = start.zip(bits).map(|(o, b)| o + b);
                    }
                }
                Step::Switch { member, arms, .. } => {
                    let m = &packet.members[*member];
                    let names: Vec<&str> = arms.iter().map(|a| a.name.as_str()).collect();
                    rows.push(LayoutRow {
                        offset_bits: offset,
                        size_bits: None,
                        name: m.name.clone(),
                        kind: format!("union of {}", names.join(" | ")),
                        nested: window.is_some(),
                    });
                    offset = None;
                }
                Step::At { member, target, root, .. } => {
                    let args = if target.args.is_empty() { "" } else { "(...)" };
                    rows.push(LayoutRow {
                        offset_bits: None,
                        size_bits: None,
                        name: packet.members[*member].name.clone(),
                        kind: format!("{}{} at {}offset ...", target.name, args, if *root { "root " } else { "" }),
                        nested: window.is_some(),
                    });
                }
                Step::Align { bytes } => {
                    let unit = bytes * 8;
                    let size = offset.map(|o| (unit - o % unit) % unit);
                    if size != Some(0) {
                        rows.push(LayoutRow {
                            offset_bits: offset,
                            size_bits: size,
                            name: "_".into(),
                            kind: format!("padding to {} byte(s)", bytes),
                            nested: false,
                        });
                    }
                    offset = offset.zip(size).map(|(o, s)| o + s);
                }
                Step::Field { member, ty, codec, array } => {
                    let elem = match codec {
                        Codec::Packet(r) => self.packets.iter().find(|p| p.name == r.name).and_then(|p| p.fixed_bits),
                        Codec::Str(StrMode::Padded | StrMode::Exact) => Some(8),
                        Codec::Str(_) | Codec::Varint(_) => None,
                        c => Some(c.bits() as u64),
                    };
                    let (size, suffix) = match array {
                        None => (elem, String::new()),
                        Some(Count::Expr(e)) => match e.const_int() {
                            Some(n) if n >= 0 => (elem.map(|b| b * n as u64), format!("[{}]", n)),
                            _ => (None, "[n]".into()),
                        },
                        Some(Count::Remaining) => (None, "[]".into()),
                        Some(Count::Until(_)) => (None, "[] until ...".into()),
                        Some(Count::Terminated { term, optional }) => (None, term_suffix(term, *optional)),
                    };
                    let kind = match (ty, codec) {
                        (_, Codec::Str(StrMode::Padded)) => format!("char{}", suffix),
                        (_, Codec::Str(StrMode::Exact)) => format!("string{}", suffix),
                        (_, Codec::Str(StrMode::CString)) => "cstring".into(),
                        (_, Codec::Str(StrMode::Terminated { term, optional })) => {
                            format!("string{}", term_suffix(term, *optional))
                        }
                        (_, Codec::Varint(k)) => format!("{}{}", k.name(), suffix),
                        (_, Codec::Str(StrMode::Prefixed { width, .. })) => format!("string(u{} prefix)", width),
                        (ValueType::Int { width: 8, signed: false }, _) if array.is_some() => {
                            format!("bytes{}", suffix)
                        }
                        (ValueType::Int { width, signed }, _) => {
                            format!("{}{}{}", if *signed { "i" } else { "u" }, width, suffix)
                        }
                        (ValueType::Float { width }, _) => format!("float{}{}", width, suffix),
                        (ValueType::Mac, _) => format!("macaddress{}", suffix),
                        (ValueType::Packet(n), Codec::Packet(r)) if !r.args.is_empty() => {
                            format!("{}(...){}", n, suffix)
                        }
                        (ValueType::Packet(n), _) => format!("{}{}", n, suffix),
                        (ValueType::Str, _) => "string".into(),
                        (ValueType::Union(n), _) => n.clone(),
                    };
                    let kind = match member.map(|m| packet.members[m].encoding) {
                        Some(enc) if enc != TextEncoding::Utf8 => format!("{} {}", kind, enc.name()),
                        _ => kind,
                    };
                    let name = member.map(|m| packet.members[m].name.clone()).unwrap_or_else(|| "_".into());
                    let kind = with_category(kind, member.map(|m| &packet.members[m]));
                    let nested = window.is_some();
                    rows.push(LayoutRow { offset_bits: offset, size_bits: size, name, kind, nested });
                    offset = offset.zip(size).map(|(o, s)| o + s);
                }
                Step::Bitfield { container_width, parts, .. } => {
                    rows.push(LayoutRow {
                        offset_bits: offset,
                        size_bits: Some(*container_width as u64),
                        name: "(bitfield)".into(),
                        kind: format!("u{} container", container_width),
                        nested: false,
                    });
                    for part in parts {
                        let m = &packet.members[part.member];
                        rows.push(LayoutRow {
                            offset_bits: offset.map(|o| o + (*container_width - part.shift - part.width) as u64),
                            size_bits: Some(part.width as u64),
                            name: m.name.clone(),
                            kind: with_category(
                                format!(
                                    "{}{} (bits {}..{})",
                                    if part.signed { "i" } else { "u" },
                                    part.width,
                                    part.shift + part.width - 1,
                                    part.shift
                                ),
                                Some(m),
                            ),
                            nested: true,
                        });
                    }
                    offset = offset.map(|o| o + *container_width as u64);
                }
            }
        }
        rows
    }
}
