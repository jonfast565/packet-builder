//! `to_json`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::ident;
use crate::generators::common::Out;
use crate::generators::common::union::variant_name;
use crate::ir::{Member, Packet, Union, ValueType};

/// Expression giving the JSON of member `m` held in `place`.
fn value(m: &Member, place: &str) -> String {
    let elem = |v: &str| match &m.ty {
        ValueType::Int { .. } => format!("format!(\"{{}}\", {})", v),
        ValueType::Float { .. } => format!("format!(\"{{:?}}\", {})", v),
        ValueType::Mac => format!("pb_json_hex(&{}[..])", v),
        ValueType::Str => format!("pb_json_str(&{})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.to_json()", v),
    };
    match &m.array {
        None => elem(place),
        Some(_) if m.ty.is_byte() => format!("pb_json_hex(&{})", place),
        Some(_) => {
            format!("format!(\"[{{}}]\", {}.iter().map(|x| {}).collect::<Vec<_>>().join(\",\"))", place, elem("x"))
        }
    }
}

/// `pub fn to_json(&self) -> String` inside the packet's `impl`.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line("/// The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.open("pub fn to_json(&self) -> String {");
    if p.members.is_empty() {
        out.line("String::from(\"{}\")");
        out.close("}");
        return;
    }
    out.line("let p = self;");
    out.line("let parts: Vec<String> = vec![");
    out.push();
    for m in &p.members {
        out.line(format!("format!(\"\\\"{}\\\":{{}}\", {}),", m.name, value(m, &format!("p.{}", ident(&m.name)))));
    }
    out.pop();
    out.line("];");
    out.line("format!(\"{{{}}}\", parts.join(\",\"))");
    out.close("}");
}

/// `impl Union { pub fn to_json(&self) -> String }`.
pub fn emit_union_json(out: &mut Out, u: &Union, generics: &str) {
    out.open(format!("impl{} {}{} {{", generics, u.name, generics));
    out.line("/// The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}.");
    out.open("pub fn to_json(&self) -> String {");
    out.open("match self {");
    for arm in &u.arms {
        let variant = variant_name(arm);
        let v = match (&arm.ty, arm.is_bytes()) {
            (None, _) => None,
            (Some(_), true) => Some("pb_json_hex(x)".to_string()),
            (Some(ValueType::Packet(_)), _) => Some("x.to_json()".to_string()),
            (Some(ValueType::Float { .. }), _) => Some("format!(\"{:?}\", x)".to_string()),
            (Some(_), _) => Some("format!(\"{}\", x)".to_string()),
        };
        match v {
            None => out.line(format!(
                "{}::{} => String::from(\"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":null}}\"),",
                u.name, variant, arm.name
            )),
            Some(v) => out.line(format!(
                "{}::{}(x) => format!(\"{{{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":{{}}}}}}\", {}),",
                u.name, variant, arm.name, v
            )),
        }
    }
    out.close("}");
    out.close("}");
    out.close("}");
}
