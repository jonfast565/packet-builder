//! `ToJSON`: every packet and union as a JSON string. Integers are numbers,
//! bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::field_name;
use crate::generators::common::Out;
use crate::generators::common::union::variant_name;
use crate::ir::{Packet, Union, ValueType};

/// Expression giving the JSON of a single value of type `ty` held in `v`.
fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { signed: true, .. } => format!("strconv.FormatInt(int64({}), 10)", v),
        ValueType::Int { .. } => format!("strconv.FormatUint(uint64({}), 10)", v),
        ValueType::Float { .. } => format!("strconv.FormatFloat(float64({}), 'g', -1, 64)", v),
        ValueType::Mac => format!("pbJSONHex({}[:])", v),
        ValueType::Str => format!("pbJSONStr({})", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.ToJSON()", v),
    }
}

pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line(format!("// ToJSON returns the {} as JSON: numbers, bytes as hex strings, unions as", p.name));
    out.line("// {\"kind\": arm, \"value\": ...}.");
    out.open(format!("func (p *{}) ToJSON() string {{", p.name));
    out.line("var b strings.Builder");
    out.line("b.WriteString(\"{\")");
    for (i, m) in p.members.iter().enumerate() {
        let sep = if i > 0 { "," } else { "" };
        out.line(format!("b.WriteString(\"{}\\\"{}\\\":\")", sep, m.name));
        let place = format!("p.{}", field_name(&m.name));
        match &m.array {
            None => out.line(format!("b.WriteString({})", elem(&m.ty, &place))),
            Some(_) if m.ty.is_byte() => out.line(format!("b.WriteString(pbJSONHex({}))", place)),
            Some(_) => {
                out.line("b.WriteString(\"[\")");
                out.open(format!("for i := range {} {{", place));
                out.open("if i > 0 {");
                out.line("b.WriteString(\",\")");
                out.close("}");
                out.line(format!("b.WriteString({})", elem(&m.ty, &format!("{}[i]", place))));
                out.close("}");
                out.line("b.WriteString(\"]\")");
            }
        }
    }
    out.line("b.WriteString(\"}\")");
    out.line("return b.String()");
    out.close("}");
}

pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("");
    out.line("// ToJSON returns the union as JSON: {\"kind\": the arm's name, \"value\": its value or null}.");
    out.open(format!("func (u *{}) ToJSON() string {{", u.name));
    out.line("value := \"null\"");
    out.line("kind := \"\"");
    out.line("switch u.Kind {");
    for arm in &u.arms {
        out.line(format!("case {}{}:", u.name, variant_name(arm)));
        out.push();
        out.line(format!("kind = \"{}\"", arm.name));
        let field = format!("u.{}", variant_name(arm));
        match (&arm.ty, arm.is_bytes()) {
            (None, _) => {}
            (Some(_), true) => out.line(format!("value = pbJSONHex({})", field)),
            (Some(ValueType::Packet(_)), _) => {
                out.open(format!("if {} != nil {{", field));
                out.line(format!("value = {}.ToJSON()", field));
                out.close("}");
            }
            (Some(t), _) => out.line(format!("value = {}", elem(t, &field))),
        }
        out.pop();
    }
    out.line("}");
    out.line("return \"{\\\"kind\\\":\\\"\" + kind + \"\\\",\\\"value\\\":\" + value + \"}\"");
    out.close("}");
}
