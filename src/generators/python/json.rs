//! `to_json`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::ident;
use crate::generators::common::Out;
use crate::ir::{Member, Packet, Union, ValueType};

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { .. } => format!("str({})", v),
        ValueType::Float { .. } => format!("repr(float({}))", v),
        ValueType::Mac => format!("_pb_json_hex({})", v),
        ValueType::Str => format!("json.dumps({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.to_json()", v),
    }
}

fn value(m: &Member, place: &str) -> String {
    match &m.array {
        None => elem(&m.ty, place),
        Some(_) if m.ty.is_byte() => format!("_pb_json_hex({})", place),
        Some(_) => format!("\"[\" + \",\".join({} for x in {}) + \"]\"", elem(&m.ty, "x"), place),
    }
}

/// `def to_json(self) -> str` inside the packet's class.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.open("def to_json(self) -> str:");
    out.line("\"\"\"The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.\"\"\"");
    out.line("p = self");
    out.line("parts = []");
    for m in &p.members {
        out.line(format!("parts.append('\"{}\":' + {})", m.name, value(m, &format!("p.{}", ident(&m.name)))));
    }
    out.line("return \"{\" + \",\".join(parts) + \"}\"");
    out.close("");
}

/// `def to_json(self) -> str` inside the union's class.
pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.open("def to_json(self) -> str:");
    out.line("\"\"\"The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}.\"\"\"");
    for arm in &u.arms {
        let v = match (&arm.ty, arm.is_bytes()) {
            (None, _) => "'null'".to_string(),
            (Some(_), true) => "_pb_json_hex(self.value)".to_string(),
            (Some(ValueType::Packet(_)), _) => "self.value.to_json()".to_string(),
            (Some(t), _) => elem(t, "self.value"),
        };
        out.open(format!("if self.kind == '{}':", arm.name));
        out.line(format!("return '{{\"kind\":\"{}\",\"value\":' + {} + '}}'", arm.name, v));
        out.pop();
    }
    out.line("return 'null'");
    out.close("");
}
