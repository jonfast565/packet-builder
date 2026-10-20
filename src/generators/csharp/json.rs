//! `ToJson`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::{arm_class, prop_name};
use crate::generators::common::Out;
use crate::ir::{Member, Packet, Union, ValueType};

const INVARIANT: &str = "System.Globalization.CultureInfo.InvariantCulture";

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { .. } => format!("{}.ToString({})", v, INVARIANT),
        ValueType::Float { .. } => format!("((double){}).ToString(\"R\", {})", v, INVARIANT),
        ValueType::Mac => format!("Pb.JsonHex({})", v),
        ValueType::Str => format!("Pb.JsonStr({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.ToJson()", v),
    }
}

fn value(m: &Member, place: &str) -> String {
    match &m.array {
        None => elem(&m.ty, place),
        Some(_) if m.ty.is_byte() => format!("Pb.JsonHex({})", place),
        Some(_) => format!("\"[\" + string.Join(\",\", {}.Select(x => {})) + \"]\"", place, elem(&m.ty, "x")),
    }
}

/// `public string ToJson()` inside the packet's class.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line(
        "/// <summary>The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.</summary>",
    );
    out.line("public string ToJson()");
    out.open("{");
    out.line("var parts = new List<string>();");
    for m in &p.members {
        let place = format!("this.{}", prop_name(&p.name, &m.name));
        out.line(format!("parts.Add(\"\\\"{}\\\":\" + {});", m.name, value(m, &place)));
    }
    out.line("return \"{\" + string.Join(\",\", parts) + \"}\";");
    out.close("}");
}

/// `public string ToJson()` inside the union's base class.
pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("");
    out.line("/// <summary>The value as JSON: {\"kind\": the arm's name, \"value\": its value or null}.</summary>");
    out.line("public string ToJson()");
    out.open("{");
    out.line("switch (this)");
    out.open("{");
    for arm in &u.arms {
        let (bind, v) = match (&arm.ty, arm.is_bytes()) {
            (None, _) => ("_", "\"null\"".to_string()),
            (Some(_), true) => ("a", "Pb.JsonHex(a.Value)".to_string()),
            (Some(t), _) => ("a", elem(t, "a.Value")),
        };
        out.line(format!(
            "case {} {}: return \"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\" + {} + \"}}\";",
            arm_class(&u.name, arm),
            bind,
            arm.name,
            v
        ));
    }
    out.close("}");
    out.line("return \"null\";");
    out.close("}");
}
