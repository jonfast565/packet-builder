//! COBOL names and the record layout of every packet.
//!
//! A packet is a record (`01 P-REC`) of fixed size: integers are
//! BINARY-DOUBLE (with an UNSIGNED view `-U`), floats FLOAT-SHORT or
//! FLOAT-LONG (with a view of their bits `-B`), MAC addresses PIC X(6),
//! nested packets their own record inline, and strings and arrays a pointer
//! (`-P`) and a length (`-N`) to memory the decoder allocates. A union is a
//! group holding the index of its arm (`-K`) and room for every arm.

use crate::generators::common::{Dialect, Out};
use crate::ir::{Arm, Member, Module, Packet, ValueType};

pub struct Cobol;

impl Dialect for Cobol {
    const TRUE: &'static str = "1";
    const FALSE: &'static str = "0";

    fn field(packet: &Packet, member: &Member) -> String {
        let i = packet.members.iter().position(|m| m.name == member.name).expect("member of its packet");
        field_name(i, &member.name)
    }
}

/// `keep_alive` → `KEEP-ALIVE`, at most `max` characters, never ending in
/// a hyphen (COBOL words are letters, digits and inner hyphens).
pub fn cob_word(s: &str, max: usize) -> String {
    let mut w: String =
        s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '-' }).take(max).collect();
    while w.ends_with('-') {
        w.pop();
    }
    while w.starts_with('-') {
        w.remove(0);
    }
    w
}

/// The record field of member `index`: `F3-LENGTH`.
pub fn field_name(index: usize, name: &str) -> String {
    let w = cob_word(name, 16);
    if w.is_empty() { format!("F{}", index) } else { format!("F{}-{}", index, w) }
}

/// The stem of the programs of packet `name`: `P2-HEADER` (`-DEC`, `-ENC`, ...).
pub fn prog(module: &Module, name: &str) -> String {
    let k = module.packets.iter().position(|p| p.name == name).expect("packet exists");
    let w = cob_word(name, 14);
    if w.is_empty() { format!("P{}", k) } else { format!("P{}-{}", k, w) }
}

/// The program `P2-HEADER-<what>` as a quoted literal for `CALL`.
pub fn call(module: &Module, name: &str, what: &str) -> String {
    format!("\"{}-{}\"", prog(module, name), what)
}

/// The local holding parameter `index`.
pub fn param_local(index: usize) -> String {
    format!("PL-P{}", index)
}

/// The local holding the encode-time value of member `index` (`pbc_<name>`).
pub fn calc_local(index: usize) -> String {
    format!("PL-C{}", index)
}

/// The local of a recorded position (`common::mark_var` names).
pub fn mark_local(var: &str) -> String {
    match var {
        "pb_start" => "PL-START".into(),
        "pbm_end" => "PL-MEND".into(),
        v => {
            let rest = v.strip_prefix("pbm_").unwrap_or(v);
            format!("PL-M{}", rest.to_ascii_uppercase())
        }
    }
}

/// The record size of packet `name` in bytes.
pub fn record_size(module: &Module, name: &str) -> u64 {
    let p = module.packets.iter().find(|p| p.name == name).expect("packet exists");
    p.members.iter().map(|m| member_size(module, m)).sum::<u64>().max(1)
}

/// The bytes a value of `ty` takes inline (scalars, union arms).
pub fn value_size(module: &Module, ty: &ValueType) -> u64 {
    match ty {
        ValueType::Int { .. } => 8,
        ValueType::Float { width: 32 } => 4,
        ValueType::Float { .. } => 8,
        ValueType::Mac => 6,
        ValueType::Packet(n) => record_size(module, n),
        ValueType::Str => 16,
        ValueType::Union(u) => {
            let u = module.union(u).expect("union exists");
            4 + u.arms.iter().map(|a| arm_size(module, a)).sum::<u64>()
        }
    }
}

pub fn arm_size(module: &Module, arm: &Arm) -> u64 {
    match &arm.ty {
        None => 0,
        Some(_) if arm.is_bytes() => 16,
        Some(t) => value_size(module, t),
    }
}

pub fn member_size(module: &Module, m: &Member) -> u64 {
    if m.array.is_some() { 16 } else { value_size(module, &m.ty) }
}

/// The bytes one array element takes: bytes are packed, other integers
/// are BINARY-DOUBLE.
pub fn elem_size(module: &Module, ty: &ValueType) -> u64 {
    if ty.is_byte() { 1 } else { value_size(module, ty) }
}

/// What `PB-INDEX` / `PB-AGG` call an element kind.
pub fn elem_kind(ty: &ValueType) -> u32 {
    match ty {
        _ if ty.is_byte() => 1,
        ValueType::Float { width: 32 } => 3,
        ValueType::Float { .. } => 4,
        _ => 2,
    }
}

/// The byte offset of member `index` in its record.
pub fn member_offset(module: &Module, p: &Packet, index: usize) -> u64 {
    p.members[..index].iter().map(|m| member_size(module, m)).sum()
}

/// Where a value lives: `val` holds it (numerically), `bits` holds a
/// float's bit pattern (a BINARY view of the same bytes).
pub struct Slot {
    pub val: String,
    pub bits: String,
}

/// The slot of a scalar field or union arm named `name`.
pub fn named_slot(name: &str) -> Slot {
    Slot { val: name.to_string(), bits: format!("{}-B", name) }
}

/// Point the LINKAGE item for a value of `ty` at `ptr` and return its slot.
pub fn point(out: &mut Out, ty: &ValueType, ptr: &str) -> Slot {
    let (group, val, bits) = match ty {
        _ if ty.is_byte() => ("LK-BY", "LK-BY", "LK-BY"),
        ValueType::Float { width: 32 } => ("LK-F4G", "LK-F4", "LK-B4"),
        ValueType::Float { .. } => ("LK-F8G", "LK-F8", "LK-B8"),
        ValueType::Mac => ("LK-MAC", "LK-MAC", "LK-MAC"),
        ValueType::Packet(_) | ValueType::Union(_) => ("LK-BLOB", "LK-BLOB", "LK-BLOB"),
        ValueType::Str => ("LK-STRG", "LK-STRG", "LK-STRG"),
        ValueType::Int { .. } => ("LK-I8G", "LK-I8", "LK-I8"),
    };
    out.line(format!("SET ADDRESS OF {} TO {}", group, ptr));
    Slot { val: val.into(), bits: bits.into() }
}

/// The LINKAGE items `point` uses.
pub fn declare_pointed(out: &mut Out) {
    out.line("01 LK-BY BINARY-CHAR UNSIGNED.");
    out.line("01 LK-I8G.");
    out.line("   05 LK-I8 BINARY-DOUBLE SIGNED.");
    out.line("   05 LK-U8 REDEFINES LK-I8 BINARY-DOUBLE UNSIGNED.");
    out.line("01 LK-F4G.");
    out.line("   05 LK-F4 FLOAT-SHORT.");
    out.line("   05 LK-B4 REDEFINES LK-F4 BINARY-LONG UNSIGNED.");
    out.line("01 LK-F8G.");
    out.line("   05 LK-F8 FLOAT-LONG.");
    out.line("   05 LK-B8 REDEFINES LK-F8 BINARY-DOUBLE SIGNED.");
    out.line("01 LK-MAC PIC X(6).");
    out.line("01 LK-STRG.");
    out.line("   05 LK-STR-P USAGE POINTER.");
    out.line("   05 LK-STR-N BINARY-DOUBLE SIGNED.");
    out.line("01 LK-SRC PIC X(65536).");
    out.line("01 LK-BLOB PIC X(65536).");
}

/// The name of the field holding arm `k` of a union field.
pub fn arm_field(base: &str, k: usize) -> String {
    format!("{}-A{}", base, k)
}

fn declare_value(out: &mut Out, module: &Module, level: u32, name: &str, ty: &ValueType) {
    match ty {
        ValueType::Int { .. } => {
            out.line(format!("{:02} {} BINARY-DOUBLE SIGNED.", level, name));
            out.line(format!("{:02} {}-U REDEFINES {} BINARY-DOUBLE UNSIGNED.", level, name, name));
        }
        ValueType::Float { width: 32 } => {
            out.line(format!("{:02} {} FLOAT-SHORT.", level, name));
            out.line(format!("{:02} {}-B REDEFINES {} BINARY-LONG UNSIGNED.", level, name, name));
        }
        ValueType::Float { .. } => {
            out.line(format!("{:02} {} FLOAT-LONG.", level, name));
            out.line(format!("{:02} {}-B REDEFINES {} BINARY-DOUBLE SIGNED.", level, name, name));
        }
        ValueType::Mac => out.line(format!("{:02} {} PIC X(6).", level, name)),
        ValueType::Packet(n) => out.line(format!("{:02} {} PIC X({}).", level, name, record_size(module, n))),
        ValueType::Str => declare_buffer(out, level, name),
        ValueType::Union(u) => {
            let u = module.union(u).expect("union exists");
            out.line(format!("{:02} {}.", level, name));
            out.line(format!("{:02} {}-K BINARY-LONG SIGNED.", level + 5, name));
            for (k, arm) in u.arms.iter().enumerate() {
                match &arm.ty {
                    None => {}
                    Some(_) if arm.is_bytes() => declare_buffer(out, level + 5, &arm_field(name, k)),
                    Some(t) => declare_value(out, module, level + 5, &arm_field(name, k), t),
                }
            }
        }
    }
}

fn declare_buffer(out: &mut Out, level: u32, name: &str) {
    out.line(format!("{:02} {}-P USAGE POINTER.", level, name));
    out.line(format!("{:02} {}-N BINARY-DOUBLE SIGNED.", level, name));
}

/// `01 <name>.` and the fields of packet `p`.
pub fn declare_record(out: &mut Out, module: &Module, p: &Packet, name: &str) {
    out.line(format!("01 {}.", name));
    out.push();
    if p.members.is_empty() {
        out.line("05 FILLER PIC X.");
    }
    for (i, m) in p.members.iter().enumerate() {
        let f = field_name(i, &m.name);
        if m.array.is_some() {
            declare_buffer(out, 5, &f);
        } else {
            declare_value(out, module, 5, &f, &m.ty);
        }
    }
    out.pop();
}

/// The message literal for `MOVE ... TO PB-MSG`: quoted, quotes doubled,
/// cut to the 256 bytes PB-MSG holds, split into `&`-joined pieces.
pub fn cob_literal(text: &str) -> String {
    let mut pieces = Vec::new();
    let mut cur = String::new();
    let mut total = 0;
    for c in text.chars() {
        if c.is_control() {
            continue;
        }
        total += c.len_utf8();
        if total > 250 {
            break;
        }
        if c == '"' {
            cur.push_str("\"\"");
        } else {
            cur.push(c);
        }
        if cur.len() >= 50 {
            pieces.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() || pieces.is_empty() {
        pieces.push(cur);
    }
    pieces.iter().map(|p| format!("\"{}\"", p)).collect::<Vec<_>>().join(" & ")
}

/// `X"0D0A"`: bytes as a hexadecimal literal.
pub fn hex_literal(bytes: &[u8]) -> String {
    format!("X\"{}\"", bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>())
}
