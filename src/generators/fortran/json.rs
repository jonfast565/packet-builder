//! `to_json`: every packet and union as a JSON string. Integers are
//! numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.
//! `<Type>_json_to` appends to a `pb_sb` string builder.

use super::locals::{Locals, body};
use super::naming::{arm_component, component, raw_string, type_name};
use crate::generators::common::Out;
use crate::ir::{Packet, Union, ValueType};

/// Append `v`, a value of `ty`; `alloc`: an allocatable packet.
fn elem(out: &mut Out, locals: &Locals, ty: &ValueType, v: &str, alloc: bool) {
    match ty {
        ValueType::Int { width: 64, signed: false } => out.line(format!("call pb_json_u(pb_j, {})", v)),
        ValueType::Int { .. } => out.line(format!("call pb_json_i(pb_j, int({}, int64))", v)),
        ValueType::Float { .. } => out.line(format!("call pb_json_f(pb_j, real({}, real64))", v)),
        ValueType::Mac => out.line(format!("call pb_json_bytes(pb_j, {})", v)),
        ValueType::Str => out.line(format!("call pb_json_str(pb_j, {})", v)),
        ValueType::Packet(n) if alloc => {
            let t = type_name(n);
            let def = locals.var(format!("pbdef_{}", t), &format!("type({})", t));
            out.open(format!("if (allocated({})) then", v));
            out.line(format!("call {}_json_to({}, pb_j)", t, v));
            out.close("else");
            out.push();
            out.line(format!("call {}_json_to({}, pb_j)", t, def));
            out.close("end if");
        }
        ValueType::Packet(n) | ValueType::Union(n) => out.line(format!("call {}_json_to({}, pb_j)", type_name(n), v)),
    }
}

fn add(out: &mut Out, text: &str) {
    out.line(format!("call pb_sb_add(pb_j, {})", raw_string(text)));
}

/// `<P>_to_json` and `<P>_json_to`; `at`: the members stored elsewhere
/// (allocatable).
pub fn packet_json(out: &mut Out, p: &Packet, at: &[usize]) {
    let t = type_name(&p.name);
    out.line("");
    out.line("!> The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.open(format!("function {}_to_json(pbv) result(pb_s)", t));
    out.line(format!("type({}), intent(in) :: pbv", t));
    out.line("character(len=:), allocatable :: pb_s");
    out.line("type(pb_sb) :: pb_j");
    out.line(format!("call {}_json_to(pbv, pb_j)", t));
    out.line("pb_s = pb_sb_text(pb_j)");
    out.close(format!("end function {}_to_json", t));

    out.line("");
    out.line(format!("recursive subroutine {}_json_to(pbv, pb_j)", t));
    let locals = Locals::default();
    let mut b = body();
    locals.var("pbv", &format!("type({}), intent(in)", t));
    locals.var("pb_j", "type(pb_sb), intent(inout)");
    add(&mut b, "{");
    for (i, m) in p.members.iter().enumerate() {
        add(&mut b, &format!("{}\"{}\":", if i == 0 { "" } else { "," }, m.name));
        let f = format!("pbv%{}", component(&m.name));
        match &m.array {
            None => elem(&mut b, &locals, &m.ty, &f, at.contains(&i)),
            Some(_) if m.ty.is_byte() => b.line(format!("call pb_json_hex(pb_j, {})", f)),
            Some(_) => {
                let n = locals.var("pbi", "integer(int64)");
                let mac = if m.ty == ValueType::Mac { "%b" } else { "" };
                add(&mut b, "[");
                b.open(format!("do {} = 1, pb_size({})", n, f));
                b.line("if (pbi > 1) call pb_sb_add(pb_j, ',')");
                elem(&mut b, &locals, &m.ty, &format!("{}(pbi){}", f, mac), false);
                b.close("end do");
                add(&mut b, "]");
            }
        }
    }
    add(&mut b, "}");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_json_to", t));
}

/// `<U>_json_to`: the arm a union holds.
pub fn union_json(out: &mut Out, u: &Union) {
    let t = type_name(&u.name);
    out.line("");
    out.line(format!("recursive subroutine {}_json_to(pbv, pb_j)", t));
    let locals = Locals::default();
    locals.var("pbv", &format!("type({}), intent(in)", t));
    locals.var("pb_j", "type(pb_sb), intent(inout)");
    let mut b = body();
    b.open("select case (pbv%pb_arm)");
    for (i, arm) in u.arms.iter().enumerate() {
        b.line(format!("case ({})", i + 1));
        b.push();
        add(&mut b, &format!("{{\"kind\":\"{}\",\"value\":", arm.name));
        let v = format!("pbv%{}", arm_component(arm));
        match &arm.ty {
            None => add(&mut b, "null"),
            Some(_) if arm.is_bytes() => b.line(format!("call pb_json_hex(pb_j, {})", v)),
            Some(ty) => elem(&mut b, &locals, ty, &v, matches!(ty, ValueType::Packet(_))),
        }
        add(&mut b, "}");
        b.pop();
    }
    b.close("end select");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_json_to", t));
}
