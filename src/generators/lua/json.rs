//! `to_json`: every packet and union as a JSON string. Integers are
//! numbers (uint64 ones unsigned), bytes are hex strings, unions are
//! `{"kind": arm, "value": ...}`.

use super::naming::class;
use crate::generators::common::Out;
use crate::generators::common::lua::index;
use crate::ir::{Member, Packet, Union, ValueType};

/// The function turning one element of type `ty` into JSON.
fn elem_fn(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width: 64, signed: false } => "pb_ustr".into(),
        ValueType::Int { .. } => "pb_json_int".into(),
        ValueType::Float { .. } => "pb_json_float".into(),
        ValueType::Mac => "pb_json_hex".into(),
        ValueType::Str => "pb_json_str".into(),
        ValueType::Packet(n) | ValueType::Union(n) => format!("{}.to_json", class(n)),
    }
}

fn value(m: &Member, place: &str) -> String {
    match &m.array {
        None => format!("{}({})", elem_fn(&m.ty), place),
        Some(_) if m.ty.is_byte() => format!("pb_json_hex({})", place),
        Some(_) => format!("pb_json_list({}, {})", place, elem_fn(&m.ty)),
    }
}

/// `C.to_json(p)` of a packet.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("-- The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.open("function C.to_json(p)");
    if p.members.is_empty() {
        out.line("return \"{}\"");
    } else {
        out.open("return \"{\" .. table.concat({");
        for m in &p.members {
            let place = format!("p{}", index(&m.name));
            out.line(format!("'\"{}\":' .. {},", m.name, value(m, &place)));
        }
        out.close("}, \",\") .. \"}\"");
    }
    out.close("end");
    out.line("");
}

/// `C.to_json(u)` of a union.
pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("-- The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}.");
    out.open("function C.to_json(u)");
    for arm in &u.arms {
        let v = match (&arm.ty, arm.is_bytes()) {
            (None, _) => "'null'".to_string(),
            (Some(_), true) => "pb_json_hex(u.value)".to_string(),
            (Some(t), _) => format!("{}(u.value)", elem_fn(t)),
        };
        out.line(format!(
            "if u.kind == \"{}\" then return '{{\"kind\":\"{}\",\"value\":' .. {} .. '}}' end",
            arm.name, arm.name, v
        ));
    }
    out.line("return 'null'");
    out.close("end");
}
