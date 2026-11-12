//! `-JSON`: print a packet's record as one JSON object (no newline).
//! Integers are numbers, bytes hex strings, unions `{"kind", "value"}`.

use super::expr::call_packet;
use super::locals::{INT, Locals, body};
use super::naming::{Slot, arm_field, cob_literal, elem_size, field_name, named_slot, point, prog};
use super::packet::{packet_linkage, program};
use crate::generators::common::Out;
use crate::ir::{Module, Packet, ValueType};

/// `DISPLAY "<text>" WITH NO ADVANCING`.
pub fn disp(out: &mut Out, text: &str) {
    out.line(format!("DISPLAY {} WITH NO ADVANCING", cob_literal(text)));
}

/// Print the `n` bytes at pointer `p` as hex.
fn hex(out: &mut Out, p: &str, n: &str) {
    out.line(format!("SET PB-WP TO {}", p));
    out.line(format!("MOVE {} TO PB-A1", n));
    out.line("CALL \"PB-JHEX\"");
}

/// Print the value of `ty` in `slot`.
fn value(out: &mut Out, module: &Module, ty: &ValueType, slot: &Slot) {
    match ty {
        ValueType::Int { signed, .. } => {
            out.line(format!("MOVE {} TO PB-X", slot.val));
            out.line(if *signed { "CALL \"PB-JI\"" } else { "CALL \"PB-JU\"" });
        }
        ValueType::Float { width: 32 } => {
            out.line(format!("MOVE {} TO PB-FS-B", slot.bits));
            out.line("CALL \"PB-JF4\"");
        }
        ValueType::Float { .. } => {
            out.line(format!("MOVE {} TO PB-FX-B", slot.bits));
            out.line("CALL \"PB-JF\"");
        }
        ValueType::Mac => {
            out.line(format!("SET PB-WP TO ADDRESS OF {}", slot.val));
            out.line("MOVE 6 TO PB-A1");
            out.line("CALL \"PB-JHEX\"");
        }
        ValueType::Str => {
            out.line(format!("SET PB-SP TO {}-P", slot.val));
            out.line(format!("MOVE {}-N TO PB-SN", slot.val));
            out.line("CALL \"PB-JSTR\"");
        }
        ValueType::Packet(n) => call_packet(out, module, n, "JSON", &slot.val, ""),
        ValueType::Union(u) => {
            let u = module.union(u).expect("union exists");
            out.open(format!("EVALUATE {}-K", slot.val));
            for (k, arm) in u.arms.iter().enumerate() {
                out.open(format!("WHEN {}", k));
                disp(out, &format!("{{\"kind\":\"{}\",\"value\":", arm.name));
                let af = arm_field(&slot.val, k);
                match &arm.ty {
                    None => disp(out, "null"),
                    Some(_) if arm.is_bytes() => hex(out, &format!("{}-P", af), &format!("{}-N", af)),
                    Some(t) => value(out, module, t, &named_slot(&af)),
                }
                disp(out, "}");
                out.pop();
            }
            out.open("WHEN OTHER");
            disp(out, "null");
            out.pop();
            out.close("END-EVALUATE");
        }
    }
}

pub fn json_program(out: &mut Out, module: &Module, p: &Packet) {
    let locals = Locals::default();
    locals.var("PL-SELF", "USAGE POINTER");
    let mut b = body();
    b.line("SET PL-SELF TO ADDRESS OF P-REC");
    disp(&mut b, "{");
    for (i, m) in p.members.iter().enumerate() {
        let f = field_name(i, &m.name);
        disp(&mut b, &format!("{}\"{}\":", if i == 0 { "" } else { "," }, m.name));
        match &m.array {
            None => value(&mut b, module, &m.ty, &named_slot(&f)),
            Some(_) if m.ty.is_byte() => hex(&mut b, &format!("{}-P", f), &format!("{}-N", f)),
            Some(_) => {
                locals.var("PL-I", INT);
                locals.var("PL-EP", "USAGE POINTER");
                locals.var("PL-OFF", INT);
                disp(&mut b, "[");
                b.open(format!("PERFORM VARYING PL-I FROM 0 BY 1 UNTIL PL-I >= {}-N", f));
                b.line("IF PL-I > 0 DISPLAY \",\" WITH NO ADVANCING END-IF");
                b.line(format!("SET PL-EP TO {}-P", f));
                b.line(format!("COMPUTE PL-OFF = PL-I * {}", elem_size(module, &m.ty)));
                b.line("SET PL-EP UP BY PL-OFF");
                let slot = point(&mut b, &m.ty, "PL-EP");
                value(&mut b, module, &m.ty, &slot);
                b.close("END-PERFORM");
                disp(&mut b, "]");
            }
        }
    }
    disp(&mut b, "}");
    b.line("GOBACK.");
    let (linkage, using) = packet_linkage(module, p, false);
    program(out, &format!("{}-JSON", prog(module, &p.name)), true, "", &locals, &linkage, &using, b);
}
