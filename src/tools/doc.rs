//! `packet_builder doc`: a Markdown reference for a description, with an
//! RFC-style bit diagram per packet, field tables, constants and categories.

use std::fmt::Write as _;

use crate::ir::{LayoutRow, Module, Packet, ValueType};

/// Bits per diagram line.
const LINE: u64 = 32;

/// `12`, `12.4` (byte 12 plus 4 bits) or `?`.
fn bytes(bits: Option<u64>) -> String {
    match bits {
        None => "?".into(),
        Some(b) if b % 8 == 0 => (b / 8).to_string(),
        Some(b) => format!("{}.{}", b / 8, b % 8),
    }
}

fn int_type(t: &ValueType) -> String {
    match t {
        ValueType::Int { width, signed } => format!("{}{}", if *signed { "i" } else { "u" }, width),
        _ => String::new(),
    }
}

/// `text` centred in `width` characters (cut if too long).
fn centre(text: &str, width: usize) -> String {
    let text: String = text.chars().take(width).collect();
    let left = (width - text.chars().count()) / 2;
    format!("{:left$}{}{:right$}", "", text, "", left = left, right = width - left - text.chars().count())
}

/// A separator line covering bits 0..`bits` of a diagram line.
fn rule(bits: u64) -> String {
    let mut s = String::from("+");
    for _ in 0..bits {
        s.push_str("-+");
    }
    s
}

/// The RFC-style diagram of the fields at fixed offsets, then one line per
/// field whose offset depends on the data.
pub fn diagram(rows: &[LayoutRow]) -> String {
    // Leaf fields: bitfield members rather than their container; windows
    // are not fields.
    let leaves: Vec<&LayoutRow> = rows
        .iter()
        .enumerate()
        .filter(|(i, r)| {
            let container = rows.get(i + 1).is_some_and(|n| n.nested) && r.name == "(bitfield)";
            !container && r.name != "(window)"
        })
        .map(|(_, r)| r)
        .collect();
    let mut out = String::new();
    out.push_str(" 0                   1                   2                   3\n");
    out.push_str(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n");
    out.push_str(&rule(LINE));
    out.push('\n');
    // Fixed part: (start, end, label) in bits.
    let mut fixed: Vec<(u64, u64, String)> = Vec::new();
    let mut rest: Vec<&LayoutRow> = Vec::new();
    for r in &leaves {
        match (r.offset_bits, r.size_bits) {
            (Some(o), Some(s)) if rest.is_empty() && s > 0 => fixed.push((o, o + s, r.name.clone())),
            (Some(_), Some(0)) if rest.is_empty() => {}
            _ => rest.push(r),
        }
    }
    let end = fixed.last().map(|f| f.1).unwrap_or(0);
    let mut line_start = 0;
    while line_start < end {
        let line_end = (line_start + LINE).min(end);
        let mut text = String::new();
        let mut bit = line_start;
        for (s, e, label) in &fixed {
            if *e <= line_start || *s >= line_end {
                continue;
            }
            let (a, b) = ((*s).max(line_start), (*e).min(line_end));
            if a > bit {
                // A gap (padding the layout leaves out).
                text.push('|');
                text.push_str(&" ".repeat((2 * (a - bit) - 1) as usize));
            }
            text.push('|');
            let shown = if *s >= line_start { label.as_str() } else { "" };
            text.push_str(&centre(shown, (2 * (b - a) - 1) as usize));
            bit = b;
        }
        text.push('|');
        out.push_str(&text);
        out.push('\n');
        out.push_str(&rule(line_end - line_start));
        out.push('\n');
        line_start = line_end;
    }
    for r in rest {
        let name = if r.name == "_" { r.kind.as_str() } else { r.name.as_str() };
        let size = match r.size_bits {
            Some(b) => format!("{} ({} bytes)", name, bytes(Some(b))),
            None => format!("{} ...", name),
        };
        out.push('/');
        out.push_str(&centre(&size, (2 * LINE - 1) as usize));
        out.push_str("/\n");
        out.push_str(&rule(LINE));
        out.push('\n');
    }
    out
}

fn packet(out: &mut String, module: &Module, p: &Packet) {
    let _ = writeln!(out, "### {}\n", p.name);
    if !p.params.is_empty() {
        let params: Vec<String> = p.params.iter().map(|x| format!("`{}` ({})", x.name, int_type(&x.ty))).collect();
        let _ = writeln!(out, "Parameters: {}.\n", params.join(", "));
    }
    match p.fixed_bits {
        Some(b) => {
            let _ = writeln!(out, "Size: {} bytes.\n", bytes(Some(b)));
        }
        None => {
            let _ = writeln!(out, "Size: variable, at least {} bytes.\n", bytes(Some(p.min_bits)));
        }
    }
    let rows = module.layout(p);
    let _ = writeln!(out, "```\n{}```\n", diagram(&rows));
    out.push_str("| offset | size | field | type |\n|-------:|-----:|-------|------|\n");
    for r in &rows {
        let name = if r.nested { format!("&nbsp;&nbsp;{}", r.name) } else { format!("`{}`", r.name) };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            bytes(r.offset_bits),
            bytes(r.size_bits),
            name,
            r.kind.replace('|', "\\|")
        );
    }
    for m in p.members.iter().filter(|m| m.is_calculated()) {
        let _ = writeln!(out, "| - | - | `{}` | calculated |", m.name);
    }
    out.push('\n');
}

/// The Markdown reference for `module`, titled `title`.
pub fn document(module: &Module, title: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# {}\n", title);
    out.push_str("Offsets and sizes are in bytes; `12.4` is byte 12 plus 4 bits, and `?` depends on the data.\n\n");
    if !module.packets.is_empty() {
        out.push_str("## Packets\n\n");
    }
    for p in &module.packets {
        packet(&mut out, module, p);
    }
    if !module.constants.is_empty() {
        out.push_str("## Constants\n\n| name | type | value | note |\n|------|------|------:|------|\n");
        for c in &module.constants {
            let note = c.note.clone().unwrap_or_default();
            let _ = writeln!(out, "| `{}` | {} | {} | {} |", c.name, int_type(&c.ty), c.literal(), note);
        }
        out.push('\n');
    }
    if !module.categories.is_empty() {
        out.push_str("## Categories\n\n");
    }
    for cat in &module.categories {
        let _ = writeln!(out, "### {} ({})\n", cat.name, int_type(&cat.ty));
        out.push_str("| name | value | note |\n|------|------:|------|\n");
        for c in &cat.members {
            let _ = writeln!(out, "| `{}` | {} | {} |", c.name, c.literal(), c.note.clone().unwrap_or_default());
        }
        out.push('\n');
    }
    out
}
