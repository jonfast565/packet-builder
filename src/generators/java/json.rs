//! `toJson`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::{arm_class, field_name};
use crate::generators::common::Out;
use crate::ir::{Member, Packet, Union, ValueType};

/// A Java expression of `v` (of type `ty`) as JSON text.
fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { width: 64, signed: false } => format!("Long.toUnsignedString({})", v),
        ValueType::Int { .. } => format!("String.valueOf({})", v),
        ValueType::Float { .. } => format!("Double.toString((double){})", v),
        ValueType::Mac => format!("Pb.jsonHex({})", v),
        ValueType::Str => format!("Pb.jsonStr({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.toJson()", v),
    }
}

/// Append member `m` (held in `place`) to the StringBuilder `sb`.
fn append(out: &mut Out, m: &Member, place: &str) {
    match &m.array {
        None => out.line(format!("sb.append({});", elem(&m.ty, place))),
        Some(_) if m.ty.is_byte() => out.line(format!("sb.append(Pb.jsonHex({}));", place)),
        Some(_) => {
            out.line("sb.append('[');");
            out.open(format!("for (int pbI = 0; pbI < {}.length; pbI++) {{", place));
            out.line("if (pbI > 0) sb.append(',');");
            out.line(format!("sb.append({});", elem(&m.ty, &format!("{}[pbI]", place))));
            out.close("}");
            out.line("sb.append(']');");
        }
    }
}

/// `public String toJson()` inside the packet's class.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line("/** The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}. */");
    out.open("public String toJson() {");
    out.line("StringBuilder sb = new StringBuilder(\"{\");");
    for (i, m) in p.members.iter().enumerate() {
        let sep = if i == 0 { "" } else { "," };
        out.line(format!("sb.append(\"{}\\\"{}\\\":\");", sep, m.name));
        append(out, m, &format!("this.{}", field_name(&m.name)));
    }
    out.line("return sb.append('}').toString();");
    out.close("}");
}

/// `public String toJson()` inside the union's base class.
pub fn emit_union_json(out: &mut Out, u: &Union, outer: &str) {
    out.line("");
    out.line("/** The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}. */");
    out.open("public String toJson() {");
    for arm in &u.arms {
        let (bind, v) = match (&arm.ty, arm.is_bytes()) {
            (None, _) => ("", "\"null\"".to_string()),
            (Some(_), true) => (" pbA", "Pb.jsonHex(pbA.value)".to_string()),
            (Some(t), _) => (" pbA", elem(t, "pbA.value")),
        };
        out.line(format!(
            "if (this instanceof {}{}) return \"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\" + {} + \"}}\";",
            arm_class(&u.name, arm, outer),
            bind,
            arm.name,
            v
        ));
    }
    out.line("return \"null\";");
    out.close("}");
}
