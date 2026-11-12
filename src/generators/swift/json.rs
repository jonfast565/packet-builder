//! `toJson`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::{case_name, ident};
use crate::generators::common::Out;
use crate::ir::{Member, Packet, Union, ValueType};

/// Expression giving the JSON of one value of type `ty` held in `v`.
fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { .. } => format!("String({})", v),
        ValueType::Float { .. } => format!("\"\\({})\"", v),
        ValueType::Mac => format!("pbJsonHex({})", v),
        ValueType::Str => format!("pbJsonStr({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.toJson()", v),
    }
}

/// Expression giving the JSON of member `m` held in `place`.
fn value(m: &Member, place: &str) -> String {
    match &m.array {
        None => elem(&m.ty, place),
        Some(_) if m.ty.is_byte() => format!("pbJsonHex({})", place),
        Some(_) => format!("\"[\" + {}.map {{ x in {} }}.joined(separator: \",\") + \"]\"", place, elem(&m.ty, "x")),
    }
}

/// `public func toJson() -> String` inside the packet's struct.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line("/// The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.open("public func toJson() -> String {");
    if p.members.is_empty() {
        out.line("return \"{}\"");
        out.close("}");
        return;
    }
    out.line("let p = self");
    out.line("var s = \"{\"");
    for (i, m) in p.members.iter().enumerate() {
        let sep = if i == 0 { "" } else { "," };
        out.line(format!("s += \"{}\\\"{}\\\":\"", sep, m.name));
        out.line(format!("s += {}", value(m, &format!("p.{}", ident(&m.name)))));
    }
    out.line("s += \"}\"");
    out.line("return s");
    out.close("}");
}

/// `public func toJson() -> String` inside the union's enum.
pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("");
    out.line("/// The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}.");
    out.open("public func toJson() -> String {");
    out.line("switch self {");
    for arm in &u.arms {
        let case = case_name(arm);
        let v = match (&arm.ty, arm.is_bytes()) {
            (None, _) => None,
            (Some(_), true) => Some("pbJsonHex(x)".to_string()),
            (Some(t), false) => Some(elem(t, "x")),
        };
        match v {
            None => {
                out.line(format!("case .{}: return \"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":null}}\"", case, arm.name))
            }
            Some(v) => out.line(format!(
                "case .{}(let x): return \"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\" + {} + \"}}\"",
                case, arm.name, v
            )),
        }
    }
    out.line("}");
    out.close("}");
}
