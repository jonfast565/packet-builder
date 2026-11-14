//! The programs of a packet: `-INIT` (defaults), `-DEC` and `-ENC` (the
//! wire format), `-JSON` (in `json.rs`) and `-FREE` (what decoding
//! allocated). Each takes the packet's record (`USING P-REC`), and the
//! decoder and encoder its parameters.

use super::decode::{Decoder, owns_bytes};
use super::encode::Encoder;
use super::expr::{RC, call_packet};
use super::locals::{FLOAT, INT, Locals, body};
use super::naming::{
    arm_field, call, cob_literal, declare_pointed, declare_record, elem_size, field_name, param_local, point, prog,
};
use crate::generators::common::{Out, StepEmitter, magic_literal};
use crate::ir::{Module, Packet, ValueType};

/// One program: its divisions around `body`, with `locals` in LOCAL-STORAGE
/// (per invocation, which recursive programs need), `storage` in
/// WORKING-STORAGE after the runtime state and `linkage` for its USING
/// parameters.
#[allow(clippy::too_many_arguments)]
pub fn program(
    out: &mut Out,
    name: &str,
    recursive: bool,
    storage: &str,
    locals: &Locals,
    linkage: &str,
    using: &str,
    body: Out,
) {
    out.line("");
    out.line("IDENTIFICATION DIVISION.");
    out.line(format!("PROGRAM-ID. {}{}.", name, if recursive { " RECURSIVE" } else { "" }));
    out.line("DATA DIVISION.");
    out.line("WORKING-STORAGE SECTION.");
    out.line("*>@STATE");
    out.buf.push_str(storage);
    locals.section(out, "LOCAL-STORAGE SECTION.");
    out.line("LINKAGE SECTION.");
    out.buf.push_str(linkage);
    out.line(format!("PROCEDURE DIVISION{}.", using));
    out.buf.push_str(&body.buf);
    out.line(format!("END PROGRAM {}.", name));
}

/// The LINKAGE of a packet program and its `USING` clause: the record,
/// then (`params`) the parameters, then the items `naming::point` uses.
pub fn packet_linkage(module: &Module, p: &Packet, params: bool) -> (String, String) {
    let mut l = Out::new("   ");
    declare_record(&mut l, module, p, "P-REC");
    let mut using = String::from(" USING P-REC");
    if params {
        for (i, x) in p.params.iter().enumerate() {
            l.line(format!("01 PA-{} {}.", i, param_usage(&x.ty)));
            using.push_str(&format!(" PA-{}", i));
        }
    }
    declare_pointed(&mut l);
    (l.buf, using)
}

pub(super) fn param_usage(ty: &ValueType) -> &'static str {
    if matches!(ty, ValueType::Float { .. }) { FLOAT } else { INT }
}

/// `-INIT`: zeros (null pointers, empty buffers), `==` values, nested
/// records initialised, unions on their first arm.
fn init_program(out: &mut Out, module: &Module, p: &Packet) {
    let locals = Locals::default();
    let mut b = body();
    b.line("MOVE LOW-VALUES TO P-REC");
    for (i, m) in p.members.iter().enumerate() {
        if m.array.is_some() {
            continue;
        }
        let f = field_name(i, &m.name);
        match &m.ty {
            ValueType::Packet(n) => b.line(format!("CALL {} USING {}", call(module, n, "INIT"), f)),
            ValueType::Union(u) => {
                let u = module.union(u).expect("union exists");
                if let (Some(ValueType::Packet(n)), false) = (&u.arms[0].ty, u.arms[0].is_bytes()) {
                    b.line(format!("CALL {} USING {}", call(module, n, "INIT"), arm_field(&f, 0)));
                }
            }
            ValueType::Int { signed, .. } => {
                if let Some(v) = magic_literal(m) {
                    b.line(format!("MOVE {} TO {}{}", v, f, if *signed { "" } else { "-U" }));
                }
            }
            _ => {}
        }
    }
    b.line("GOBACK.");
    let (linkage, using) = packet_linkage(module, p, false);
    program(out, &format!("{}-INIT", prog(module, &p.name)), false, "", &locals, &linkage, &using, b);
}

/// The start of `-DEC` and `-ENC`: remember the record, take the
/// parameters, enter the packet's frame of the trace.
fn prologue(b: &mut Out, locals: &Locals, p: &Packet) {
    locals.var("PL-SELF", "USAGE POINTER");
    b.line("SET PL-SELF TO ADDRESS OF P-REC");
    for (i, x) in p.params.iter().enumerate() {
        locals.var(param_local(i), param_usage(&x.ty));
        b.line(format!("MOVE PA-{} TO {}", i, param_local(i)));
    }
}

fn enter(b: &mut Out, locals: &Locals, p: &Packet) {
    b.line(format!("MOVE {} TO PB-NAME", cob_literal(&p.name)));
    b.line("CALL \"PB-ENTER\"");
    b.line(RC);
    if let Some(scope) = p.version_scope {
        locals.var("PL-SCOPE", INT);
        b.line(format!("MOVE {} TO PB-A1", scope));
        b.line("CALL \"PB-ENTERSC\"");
        b.line(RC);
        b.line("MOVE PB-A2 TO PL-SCOPE");
    }
}

/// Leave the packet's frame of the trace (and its version scope).
fn leave(b: &mut Out, p: &Packet) {
    if p.version_scope.is_some() {
        b.line("MOVE PL-SCOPE TO PB-A1");
        b.line("CALL \"PB-LEAVESC\"");
        b.line(RC);
    }
    b.line("SUBTRACT 1 FROM PB-DEPTH");
}

fn decode_program(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
    let locals = Locals::default();
    let mut b = body();
    prologue(&mut b, &locals, p);
    b.line(format!("CALL {} USING P-REC", call(module, &p.name, "INIT")));
    enter(&mut b, &locals, p);
    if p.needs_start(false) {
        locals.var("PL-START", INT);
        b.line("MOVE PB-POS TO PL-START");
    }
    Decoder::new(module, p, &locals, zero_copy).emit_steps(&mut b);
    leave(&mut b, p);
    b.line("GOBACK.");
    let (linkage, using) = packet_linkage(module, p, true);
    program(out, &format!("{}-DEC", prog(module, &p.name)), true, "", &locals, &linkage, &using, b);
}

fn encode_program(out: &mut Out, module: &Module, p: &Packet) {
    let locals = Locals::default();
    let mut b = body();
    prologue(&mut b, &locals, p);
    enter(&mut b, &locals, p);
    if p.needs_start(true) {
        locals.var("PL-START", INT);
        b.line("MOVE PB-WPOS TO PL-START");
    }
    let encoder = Encoder::new(module, p, &locals);
    encoder.emit_locals(&mut b);
    encoder.emit_steps(&mut b);
    leave(&mut b, p);
    b.line("GOBACK.");
    let (linkage, using) = packet_linkage(module, p, true);
    program(out, &format!("{}-ENC", prog(module, &p.name)), true, "", &locals, &linkage, &using, b);
}

/// `FREE <ptr>` unless it is null.
fn free(b: &mut Out, ptr: &str) {
    b.line(format!("IF {} NOT = NULL FREE {} END-IF", ptr, ptr));
}

/// `-FREE`: release what decoding (or setting a string) allocated, and
/// leave the record empty.
fn free_program(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
    let locals = Locals::default();
    locals.var("PL-SELF", "USAGE POINTER");
    let mut b = body();
    b.line("SET PL-SELF TO ADDRESS OF P-REC");
    for (i, m) in p.members.iter().enumerate() {
        let f = field_name(i, &m.name);
        if m.array.is_some() {
            if let ValueType::Packet(n) = &m.ty {
                locals.var("PL-I", INT);
                locals.var("PL-EP", "USAGE POINTER");
                locals.var("PL-OFF", INT);
                b.open(format!("IF {}-P NOT = NULL", f));
                b.open(format!("PERFORM VARYING PL-I FROM 0 BY 1 UNTIL PL-I >= {}-N", f));
                b.line(format!("SET PL-EP TO {}-P", f));
                b.line(format!("COMPUTE PL-OFF = PL-I * {}", elem_size(module, &m.ty)));
                b.line("SET PL-EP UP BY PL-OFF");
                let slot = point(&mut b, &m.ty, "PL-EP");
                call_packet(&mut b, module, n, "FREE", &slot.val, "");
                b.close("END-PERFORM");
                b.close("END-IF");
            }
            if !m.ty.is_byte() || owns_bytes(p, i, zero_copy) {
                free(&mut b, &format!("{}-P", f));
            }
            continue;
        }
        match &m.ty {
            ValueType::Str => free(&mut b, &format!("{}-P", f)),
            ValueType::Packet(n) => call_packet(&mut b, module, n, "FREE", &f, ""),
            ValueType::Union(u) => {
                let u = module.union(u).expect("union exists");
                let owning = |arm: &crate::ir::Arm| match &arm.ty {
                    Some(_) if arm.is_bytes() => !zero_copy,
                    Some(ValueType::Str | ValueType::Packet(_)) => true,
                    _ => false,
                };
                if !u.arms.iter().any(owning) {
                    continue;
                }
                b.open(format!("EVALUATE {}-K", f));
                for (k, arm) in u.arms.iter().enumerate().filter(|(_, a)| owning(a)) {
                    let af = arm_field(&f, k);
                    b.open(format!("WHEN {}", k));
                    match &arm.ty {
                        Some(ValueType::Packet(n)) if !arm.is_bytes() => {
                            call_packet(&mut b, module, n, "FREE", &af, "")
                        }
                        _ => free(&mut b, &format!("{}-P", af)),
                    }
                    b.pop();
                }
                b.open("WHEN OTHER");
                b.line("CONTINUE");
                b.pop();
                b.close("END-EVALUATE");
            }
            _ => {}
        }
    }
    b.line("MOVE LOW-VALUES TO P-REC");
    b.line("GOBACK.");
    let (linkage, using) = packet_linkage(module, p, false);
    program(out, &format!("{}-FREE", prog(module, &p.name)), true, "", &locals, &linkage, &using, b);
}

/// Every program of packet `p`.
pub fn packet_programs(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
    out.line("");
    out.line(format!("*> ---- packet {} {}", p.name, "-".repeat(60usize.saturating_sub(p.name.len()))));
    init_program(out, module, p);
    decode_program(out, module, p, zero_copy);
    encode_program(out, module, p);
    super::json::json_program(out, module, p);
    free_program(out, module, p, zero_copy);
    super::stream::stream_programs(out, module, p);
}
