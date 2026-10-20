//! Field-by-field layout report (the `layout` command).

use super::model::{Codec, Count, Member, Module, Packet, Step, StrMode, ValueType};

/// `u8` becomes `u8 : Channel` for a member tagged with a category.
fn with_category(kind: String, member: Option<&Member>) -> String {
    match member.and_then(|m| m.category.as_ref()) {
        Some(c) => format!("{} : {}", kind, c),
        None => kind,
    }
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
        let mut rows = Vec::new();
        let mut offset = Some(0u64);
        for step in &packet.steps {
            match step {
                Step::Calc { .. } => {}
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
                        Codec::Packet(n) => self.packets.iter().find(|p| &p.name == n).and_then(|p| p.fixed_bits),
                        Codec::Str(StrMode::Padded | StrMode::Exact) => Some(8),
                        Codec::Str(_) => None,
                        c => Some(c.bits() as u64),
                    };
                    let (size, suffix) = match array {
                        None => (elem, String::new()),
                        Some(Count::Expr(e)) => match e.const_int() {
                            Some(n) if n >= 0 => (elem.map(|b| b * n as u64), format!("[{}]", n)),
                            _ => (None, "[n]".into()),
                        },
                        Some(Count::Remaining) => (None, "[]".into()),
                    };
                    let kind = match (ty, codec) {
                        (_, Codec::Str(StrMode::Padded)) => format!("char{}", suffix),
                        (_, Codec::Str(StrMode::Exact)) => format!("string{}", suffix),
                        (_, Codec::Str(StrMode::CString)) => "cstring".into(),
                        (_, Codec::Str(StrMode::Prefixed { width, .. })) => format!("string(u{} prefix)", width),
                        (ValueType::Int { width: 8, signed: false }, _) if array.is_some() => {
                            format!("bytes{}", suffix)
                        }
                        (ValueType::Int { width, signed }, _) => {
                            format!("{}{}{}", if *signed { "i" } else { "u" }, width, suffix)
                        }
                        (ValueType::Float { width }, _) => format!("float{}{}", width, suffix),
                        (ValueType::Mac, _) => format!("macaddress{}", suffix),
                        (ValueType::Packet(n), _) => format!("{}{}", n, suffix),
                        (ValueType::Str, _) => "string".into(),
                    };
                    let name = member.map(|m| packet.members[m].name.clone()).unwrap_or_else(|| "_".into());
                    let kind = with_category(kind, member.map(|m| &packet.members[m]));
                    rows.push(LayoutRow { offset_bits: offset, size_bits: size, name, kind, nested: false });
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
