//! `To_Json`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::encode::unboxed;
use super::locals::{Locals, body};
use super::naming::{ada_string, arm_literal, ident, type_name};
use super::types::Boxes;
use crate::generators::common::Out;
use crate::ir::{Packet, Union, ValueType};

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { signed: true, .. } => format!("Pb_Json_I (Pb_I ({}))", v),
        ValueType::Int { signed: false, .. } => format!("Pb_Json_U (Pb_U ({}))", v),
        ValueType::Float { .. } => format!("Pb_Json_F (Pb_F ({}))", v),
        ValueType::Mac => format!("Pb_Json_Mac ({})", v),
        ValueType::Str => format!("Pb_Json_Str ({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("To_Json ({})", v),
    }
}

pub fn declare_packet_json(out: &mut Out, p: &Packet) {
    out.line("--  The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.line(format!("function To_Json (P : {}) return String;", type_name(&p.name)));
}

pub fn implement_packet_json(out: &mut Out, p: &Packet, boxes: &Boxes) {
    out.line("");
    let header = format!("function To_Json (P : {}) return String", type_name(&p.name));
    let locals = Locals::default();
    locals.var("Pb_J", "Pb_SU.Unbounded_String");
    let mut b = body();
    b.line("Pb_SU.Append (Pb_J, \"{\");");
    for (i, m) in p.members.iter().enumerate() {
        let f = format!("P.{}", ident(&m.name));
        let key = ada_string(&format!("{}\"{}\":", if i == 0 { "" } else { "," }, m.name));
        match &m.array {
            None => {
                let v = unboxed(f, boxes.member(&p.name, &m.name));
                b.line(format!("Pb_SU.Append (Pb_J, {} & {});", key, elem(&m.ty, &v)));
            }
            Some(_) if m.ty.is_byte() => b.line(format!("Pb_SU.Append (Pb_J, {} & Pb_Json_Hex ({}));", key, f)),
            Some(_) => {
                b.line(format!("Pb_SU.Append (Pb_J, {} & \"[\");", key));
                b.open(format!("for Pb_K in 0 .. Integer ({}.Length) - 1 loop", f));
                b.line("if Pb_K > 0 then");
                b.line("   Pb_SU.Append (Pb_J, \",\");");
                b.line("end if;");
                b.line(format!("Pb_SU.Append (Pb_J, {});", elem(&m.ty, &format!("{}.Element (Pb_K)", f))));
                b.close("end loop;");
                b.line("Pb_SU.Append (Pb_J, \"]\");");
            }
        }
    }
    b.line("Pb_SU.Append (Pb_J, \"}\");");
    b.line("return Pb_SU.To_String (Pb_J);");
    locals.routine(out, &header, "To_Json", b);
}

pub fn declare_union_json(out: &mut Out, u: &Union) {
    out.line(format!("function To_Json (U : {}) return String;", type_name(&u.name)));
}

pub fn implement_union_json(out: &mut Out, u: &Union, boxes: &Boxes) {
    out.line("");
    out.line(format!("function To_Json (U : {}) return String is", type_name(&u.name)));
    out.line("begin");
    out.push();
    out.open("case U.Kind is");
    for arm in &u.arms {
        let v = match (&arm.ty, arm.is_bytes()) {
            (None, _) => "\"null\"".to_string(),
            (Some(_), true) => format!("Pb_Json_Hex (U.{})", ident(&arm.name)),
            (Some(t), _) => elem(t, &unboxed(format!("U.{}", ident(&arm.name)), boxes.member(&u.name, &arm.name))),
        };
        out.line(format!("when {} =>", arm_literal(&u.name, arm)));
        out.line(format!(
            "   return {} & {} & \"}}\";",
            ada_string(&format!("{{\"kind\":\"{}\",\"value\":", arm.name)),
            v
        ));
    }
    out.close("end case;");
    out.pop();
    out.line("end To_Json;");
}
