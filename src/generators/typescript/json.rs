//! `toJson`: every packet and union as a JSON string. Integers are numbers,
//! bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::{ident, type_name};
use crate::generators::common::Out;
use crate::ir::{Member, Packet, Union, ValueType};

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { .. } => format!("String({})", v),
        ValueType::Float { .. } => format!("pbJsonF({})", v),
        ValueType::Mac => format!("pbJsonHex({})", v),
        ValueType::Str => format!("JSON.stringify({})", v),
        ValueType::Packet(_) => format!("{}.toJson()", v),
        ValueType::Union(u) => format!("{}.toJson({})", type_name(u), v),
    }
}

fn value(m: &Member, place: &str) -> String {
    match &m.array {
        None => elem(&m.ty, place),
        Some(_) if m.ty.is_byte() => format!("pbJsonHex({})", place),
        Some(_) => format!("\"[\" + {}.map((x) => {}).join(\",\") + \"]\"", place, elem(&m.ty, "x")),
    }
}

/// `toJson(): string` inside the packet's class.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("/** The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}. */");
    out.open("toJson(): string {");
    if p.members.is_empty() {
        out.line("return \"{}\";");
        out.close("}");
        return;
    }
    out.line("const p = this;");
    out.line("const parts: string[] = [];");
    for m in &p.members {
        out.line(format!("parts.push('\"{}\":' + {});", m.name, value(m, &format!("p.{}", ident(&m.name)))));
    }
    out.line("return \"{\" + parts.join(\",\") + \"}\";");
    out.close("}");
}

/// `toJson(u)` in the union's helper object.
pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("/** The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}. */");
    out.open(format!("toJson(u: {}): string {{", type_name(&u.name)));
    for arm in &u.arms {
        let v = match (&arm.ty, arm.is_bytes()) {
            (None, _) => {
                out.line(format!(
                    "if (u.kind === \"{}\") return '{{\"kind\":\"{}\",\"value\":null}}';",
                    arm.name, arm.name
                ));
                continue;
            }
            (Some(_), true) => "pbJsonHex(u.value)".to_string(),
            (Some(t), _) => elem(t, "u.value"),
        };
        out.line(format!(
            "if (u.kind === \"{}\") return '{{\"kind\":\"{}\",\"value\":' + {} + \"}}\";",
            arm.name, arm.name, v
        ));
    }
    out.line("return \"null\";");
    out.close("},");
}
