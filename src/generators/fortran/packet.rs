//! A derived type per packet and union, and the procedures of each packet:
//! `<P>_decode`, `<P>_decode_from`, `<P>_encode`, `<P>_encode_to`,
//! `<P>_to_json` and the stream helpers.

use super::decode::{Decoder, R_FAILED};
use super::encode::{Encoder, W_FAILED};
use super::locals::{Locals, body};
use super::naming::{arm_component, arm_tag, member_decl, raw_string, scalar_type, type_name};
use super::stream::set_version;
use crate::generators::common::{Out, StepEmitter, member_category, param_var};
use crate::ir::{Module, Packet, Step, Union, ValueType};

/// The members of `p` stored elsewhere (`at`): allocatable components.
pub fn at_members(p: &Packet) -> Vec<usize> {
    p.steps
        .iter()
        .filter_map(|s| match s {
            Step::At { member, .. } => Some(*member),
            _ => None,
        })
        .collect()
}

/// Packets ordered so that each comes after the packets it holds by value
/// (union arms and `at` members are allocatable, arrays too).
pub fn type_order(module: &Module) -> Vec<&Packet> {
    fn visit<'a>(m: &'a Module, p: &'a Packet, seen: &mut Vec<String>, out: &mut Vec<&'a Packet>) {
        if seen.contains(&p.name) {
            return;
        }
        seen.push(p.name.clone());
        let at = at_members(p);
        for (i, member) in p.members.iter().enumerate() {
            if member.array.is_some() || at.contains(&i) {
                continue;
            }
            if let ValueType::Packet(n) = &member.ty
                && let Some(dep) = m.packets.iter().find(|x| &x.name == n)
            {
                visit(m, dep, seen, out);
            }
        }
        out.push(p);
    }
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for p in &module.packets {
        visit(module, p, &mut seen, &mut out);
    }
    out
}

/// The component holding an arm's value.
fn arm_decl(u: &Union, i: usize) -> Option<String> {
    let arm = &u.arms[i];
    let ty = arm.ty.as_ref()?;
    let name = arm_component(arm);
    Some(match ty {
        _ if arm.is_bytes() => format!("integer(int8), allocatable :: {}(:)", name),
        ValueType::Packet(n) => format!("type({}), allocatable :: {}", type_name(n), name),
        ValueType::Str => format!("character(len=:), allocatable :: {}", name),
        ValueType::Mac => format!("integer(int8) :: {}(6) = 0_int8", name),
        _ => format!("{} :: {} = 0", scalar_type(ty), name),
    })
}

pub fn declare_union(out: &mut Out, u: &Union, tags: &[String]) {
    let t = type_name(&u.name);
    for (i, (arm, tag)) in u.arms.iter().zip(tags).enumerate() {
        let what = if arm.default {
            "any other selector value".to_string()
        } else {
            let v: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            format!("selector {}", v.join(", "))
        };
        out.line(format!("!> Union {} holds arm {} ({}).", u.name, arm.name, what));
        out.line(format!("integer, parameter :: {} = {}", tag, i + 1));
    }
    out.line(format!("!> Union {}: pb_arm says which arm (component) holds the value.", u.name));
    out.open(format!("type :: {}", t));
    out.line("integer :: pb_arm = 1");
    for i in 0..u.arms.len() {
        if let Some(d) = arm_decl(u, i) {
            out.line(d);
        }
    }
    out.close(format!("end type {}", t));
}

/// The names of the union arm tags (`<Union>_<arm>`).
pub fn default_tags(u: &Union) -> Vec<String> {
    u.arms.iter().map(|a| arm_tag(u, a)).collect()
}

pub fn declare_packet(out: &mut Out, p: &Packet) {
    let t = type_name(&p.name);
    let at = at_members(p);
    out.open(format!("type :: {}", t));
    for (i, m) in p.members.iter().enumerate() {
        if let Some(cat) = member_category(m) {
            out.line(format!("!> Values from {}.", cat));
        }
        out.line(member_decl(m, at.contains(&i)));
    }
    if p.members.is_empty() {
        // A derived type needs a component.
        out.line("integer :: pb_empty = 0");
    }
    out.close(format!("end type {}", t));
}

/// `, pbp_a, pbp_b`: the parameters in a signature or passed on.
fn param_list(p: &Packet) -> String {
    p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect()
}

fn declare_params(locals: &Locals, p: &Packet) {
    for x in &p.params {
        locals.var(param_var(&x.name), &format!("{}, intent(in)", scalar_type(&x.ty)));
    }
}

/// `pb_size` for arrays of packet `p`.
pub fn size_function(out: &mut Out, p: &Packet) {
    let t = type_name(&p.name);
    out.line("");
    out.open(format!("pure function pb_size_{}(a) result(n)", t));
    out.line(format!("type({}), allocatable, intent(in) :: a(:)", t));
    out.line("integer(int64) :: n");
    out.line("n = 0");
    out.line("if (allocated(a)) n = size(a, kind=int64)");
    out.close(format!("end function pb_size_{}", t));
}

pub fn union_procedures(out: &mut Out, u: &Union) {
    super::json::union_json(out, u);
}

pub fn packet_procedures(out: &mut Out, module: &Module, p: &Packet) {
    let t = type_name(&p.name);
    let params = param_list(p);
    let ver = if p.versions.is_some() { ", pb_version" } else { "" };

    out.line("");
    if let Some((min, latest)) = p.versions.map(|_| p.version_bounds()) {
        out.line(format!(
            "!> Decode from the start of PB_DATA; trailing bytes are ignored. PB_VERSION: the protocol version ({}..{}); 0 or absent: the one in the data, or the latest.",
            min, latest
        ));
    } else {
        out.line("!> Decode from the start of PB_DATA; trailing bytes are ignored. PB_ERR%kind is PB_OK on success.");
    }
    out.line(format!("subroutine {}_decode(pbv, pb_data, pb_err{}{})", t, params, ver));
    let locals = Locals::default();
    locals.var("pbv", &format!("type({}), intent(out)", t));
    locals.var("pb_data(:)", "integer(int8), intent(in)");
    locals.var("pb_err", "type(pb_error), intent(out)");
    declare_params(&locals, p);
    if p.versions.is_some() {
        locals.var("pb_version", "integer, intent(in), optional");
    }
    locals.var("pb_r", "type(pb_reader)");
    let mut b = body();
    b.line("call pb_reader_init(pb_r, pb_data)");
    set_version(&mut b, p, "pb_r");
    b.line(format!("if (pb_r%e%kind == PB_OK) call {}_decode_from(pbv, pb_r{})", t, params));
    b.line("pb_err = pb_r%e");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_decode", t));

    out.line("");
    out.line(format!("recursive subroutine {}_decode_from(pbv, pb_r{})", t, params));
    let locals = Locals::default();
    locals.var("pbv", &format!("type({}), intent(out)", t));
    locals.var("pb_r", "type(pb_reader), intent(inout)");
    declare_params(&locals, p);
    let mut b = body();
    b.line(format!("call pb_enter(pb_r, {})", raw_string(&p.name)));
    b.line(R_FAILED);
    if let Some(scope) = p.version_scope {
        locals.var("pb_scope", "logical");
        b.line(format!("call pb_enter_scope(pb_r, {}, pb_scope)", scope));
    }
    if p.needs_start(false) {
        locals.var("pb_start", "integer(int64)");
        b.line("pb_start = pb_r%pos");
    }
    Decoder::new(p, &locals).emit_steps(&mut b);
    if p.version_scope.is_some() {
        b.line("call pb_leave_scope(pb_r, pb_scope)");
    }
    b.line("call pb_leave(pb_r)");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_decode_from", t));

    out.line("");
    out.line("!> Encode PBV into PB_OUT (empty when PB_ERR%kind is not PB_OK).");
    out.line(format!("subroutine {}_encode(pbv, pb_out, pb_err{}{})", t, params, ver));
    let locals = Locals::default();
    locals.var("pbv", &format!("type({}), intent(in)", t));
    locals.var("pb_out(:)", "integer(int8), allocatable, intent(out)");
    locals.var("pb_err", "type(pb_error), intent(out)");
    declare_params(&locals, p);
    if p.versions.is_some() {
        locals.var("pb_version", "integer, intent(in), optional");
    }
    locals.var("pb_w", "type(pb_writer)");
    let mut b = body();
    set_version(&mut b, p, "pb_w");
    b.line(format!("if (pb_w%e%kind == PB_OK) call {}_encode_to(pbv, pb_w{})", t, params));
    b.line("if (pb_w%e%kind == PB_OK) call pb_finish(pb_w, pb_out)");
    b.line("pb_err = pb_w%e");
    b.open("if (pb_err%kind /= PB_OK) then");
    b.line("if (allocated(pb_out)) deallocate(pb_out)");
    b.line("allocate(pb_out(0))");
    b.close("end if");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_encode", t));

    out.line("");
    out.line(format!("recursive subroutine {}_encode_to(pbv, pb_w{})", t, params));
    let locals = Locals::default();
    locals.var("pbv", &format!("type({}), intent(in)", t));
    locals.var("pb_w", "type(pb_writer), intent(inout)");
    declare_params(&locals, p);
    let mut b = body();
    b.line(format!("call pb_enter(pb_w, {})", raw_string(&p.name)));
    b.line(W_FAILED);
    if let Some(scope) = p.version_scope {
        locals.var("pb_scope", "logical");
        b.line(format!("call pb_enter_scope(pb_w, {}, pb_scope)", scope));
    }
    if p.needs_start(true) {
        locals.var("pb_start", "integer(int64)");
        b.line("pb_start = pb_w%pos");
    }
    let encoder = Encoder::new(p, &locals);
    encoder.emit_locals(&mut b);
    encoder.emit_steps(&mut b);
    if p.version_scope.is_some() {
        b.line("call pb_leave_scope(pb_w, pb_scope)");
    }
    b.line("call pb_leave(pb_w)");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_encode_to", t));

    super::json::packet_json(out, p, &at_members(p));
    super::stream::streaming(out, module, p);
}
