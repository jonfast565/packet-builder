//! A readable, indented rendering of decoded values.

use std::fmt::Write as _;

use super::value::{Struct, Value};
use crate::ir::{Member, Module};

/// Longest byte buffer shown in full; longer ones are cut with a count.
const MAX_BYTES: usize = 32;

/// Render a decoded packet as an indented tree:
/// ```text
/// Flap
///   start: 42 (0x2a)
///   channel: 2 (Channel.snac)
///   payload: 0017000600... (54 bytes)
/// ```
pub fn render(module: &Module, value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Struct(s) => {
            out.push_str(&s.packet);
            out.push('\n');
            fields(module, s, 1, &mut out);
        }
        other => {
            out.push_str(&scalar(module, None, other));
            out.push('\n');
        }
    }
    out
}

fn fields(module: &Module, s: &Struct, depth: usize, out: &mut String) {
    let packet = module.packets.iter().find(|p| p.name == s.packet);
    for (name, v) in &s.fields {
        let m = packet.and_then(|p| p.members.iter().find(|m| &m.name == name));
        let calc = if m.map(|m| m.is_calculated()).unwrap_or(false) { " (calculated)" } else { "" };
        entry(module, m, &format!("{}{}", name, calc), v, depth, out);
    }
}

fn entry(module: &Module, m: Option<&Member>, label: &str, v: &Value, depth: usize, out: &mut String) {
    let pad = "  ".repeat(depth);
    match v {
        Value::Struct(s) => {
            let _ = writeln!(out, "{}{}: {}", pad, label, s.packet);
            fields(module, s, depth + 1, out);
        }
        Value::Variant { arm, value } => match value {
            Some(v) => entry(module, None, &format!("{} ({})", label, arm), v, depth, out),
            None => {
                let _ = writeln!(out, "{}{}: {}", pad, label, arm);
            }
        },
        Value::List(items) => {
            let _ = writeln!(out, "{}{}: {} item(s)", pad, label, items.len());
            for (i, item) in items.iter().enumerate() {
                entry(module, m, &format!("[{}]", i), item, depth + 1, out);
            }
        }
        other => {
            let _ = writeln!(out, "{}{}: {}", pad, label, scalar(module, m, other));
        }
    }
}

fn scalar(module: &Module, m: Option<&Member>, v: &Value) -> String {
    match v {
        Value::Int(i) => {
            let named = m.and_then(|m| m.category.as_ref()).and_then(|cat| {
                let c = module.categories.iter().find(|c| &c.name == cat)?;
                let hit = c.members.iter().find(|k| k.value as i128 == *i || k.value as u64 as i128 == *i)?;
                Some(format!("{}.{}", c.name, hit.name))
            });
            match named {
                Some(n) => format!("{} ({})", i, n),
                None if *i > 9 => format!("{} (0x{:x})", i, i),
                None => i.to_string(),
            }
        }
        Value::Float(f) => format!("{}", f),
        Value::Bytes(b) if b.is_empty() => "(empty)".into(),
        Value::Bytes(b) => {
            let shown: String = b.iter().take(MAX_BYTES).map(|x| format!("{:02x}", x)).collect();
            if b.len() > MAX_BYTES {
                format!("{}... ({} bytes)", shown, b.len())
            } else {
                format!("{} ({} byte{})", shown, b.len(), if b.len() == 1 { "" } else { "s" })
            }
        }
        Value::Str(s) => format!("{:?}", s),
        Value::List(_) | Value::Struct(_) | Value::Variant { .. } => String::new(),
    }
}
