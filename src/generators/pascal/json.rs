//! `ToJson`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::locals::{Locals, body};
use super::naming::{arm_class, ident, pas_string, type_name};
use crate::generators::common::Out;
use crate::ir::{Arm, Packet, Union, ValueType};

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { signed: true, .. } => format!("PbJsonI({})", v),
        ValueType::Int { signed: false, .. } => format!("PbJsonU({})", v),
        ValueType::Float { .. } => format!("PbJsonF({})", v),
        ValueType::Mac => format!("PbJsonHex({})", v),
        ValueType::Str => format!("PbJsonStr({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.ToJson", v),
    }
}

pub fn implement_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line(format!("function {}.ToJson: string;", type_name(&p.name)));
    let locals = Locals::default();
    let mut b = body();
    b.line("Result := '{';");
    for (i, m) in p.members.iter().enumerate() {
        let f = ident(&m.name);
        let key = pas_string(&format!("{}\"{}\":", if i == 0 { "" } else { "," }, m.name));
        match &m.array {
            None => b.line(format!("Result := Result + {} + {};", key, elem(&m.ty, &f))),
            Some(_) if m.ty.is_byte() => b.line(format!("Result := Result + {} + PbJsonHex({});", key, f)),
            Some(_) => {
                locals.var("pbI", "Integer");
                b.line(format!("Result := Result + {} + '[';", key));
                b.line(format!("for pbI := 0 to High({}) do", f));
                b.open("begin");
                b.line("if pbI > 0 then Result := Result + ',';");
                b.line(format!("Result := Result + {};", elem(&m.ty, &format!("{}[pbI]", f))));
                b.close("end;");
                b.line("Result := Result + ']';");
            }
        }
    }
    b.line("Result := Result + '}';");
    locals.routine(out, b);
}

pub fn implement_arm_json(out: &mut Out, u: &Union, arm: &Arm) {
    let v = match (&arm.ty, arm.is_bytes()) {
        (None, _) => "'null'".to_string(),
        (Some(_), true) => "PbJsonHex(Value)".to_string(),
        (Some(t), _) => elem(t, "Value"),
    };
    out.line("");
    out.line(format!("function {}.ToJson: string;", arm_class(&u.name, arm)));
    out.open("begin");
    out.line(format!("Result := {} + {} + '}}';", pas_string(&format!("{{\"kind\":\"{}\",\"value\":", arm.name)), v));
    out.close("end;");
}
