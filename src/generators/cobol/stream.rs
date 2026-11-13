//! The stream helpers and the driver programs.
//!
//! `-FRAME` is `frame_len`: a packet's size from its header (PB-FRC 0 and
//! PB-FLEN, 1 while the header is incomplete, 2 for a bad length). `-RUN`
//! runs one line of the `.dat` file the main program reads: decode the
//! bytes in PB-IN, apply the line's `path=value` settings, print the value
//! and the re-encoded bytes as one JSON line, then what `try_decode` and
//! `frame_len` say as a second line. Try-decoding is decoding: the reader
//! only reports `incomplete` at the end of the real input, with the bits
//! still needed.

use super::decode::little;
use super::expr::{Ev, store_value};
use super::json::disp;
use super::locals::{INT, Locals, body};
use super::naming::{
    call, cob_literal, declare_pointed, declare_record, field_name, member_offset, point, prog, record_size,
};
use super::packet::{param_usage, program};
use crate::generators::common::{Mode, Out};
use crate::ir::{Codec, Module, Packet, ValueType, storage_for};

/// The members a `.dat` line can set: scalar integers, floats and strings,
/// also inside nested packets (`table.first`), with their byte offsets.
fn settable(module: &Module, p: &Packet, prefix: &str, base: u64, depth: u32, out: &mut Vec<(String, u64, ValueType)>) {
    for (i, m) in p.members.iter().enumerate() {
        if m.array.is_some() {
            continue;
        }
        let off = base + member_offset(module, p, i);
        let path = format!("{}{}", prefix, m.name);
        match &m.ty {
            ValueType::Int { .. } | ValueType::Float { .. } | ValueType::Str => out.push((path, off, m.ty.clone())),
            ValueType::Packet(n) if depth < 3 => {
                let q = module.packets.iter().find(|q| &q.name == n).expect("packet exists");
                settable(module, q, &format!("{}.", path), off, depth + 1, out);
            }
            _ => {}
        }
    }
}

fn set_version(b: &mut Out, p: &Packet) {
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        b.open("IF PB-CVER NOT = 0");
        b.line("MOVE PB-CVER TO PB-A1");
        b.line(format!("MOVE {} TO PB-A2", min));
        b.line(format!("MOVE {} TO PB-A3", latest));
        b.line("CALL \"PB-SETVER\"");
        b.close("END-IF");
    }
}

fn run_program(out: &mut Out, module: &Module, p: &Packet) {
    let locals = Locals::default();
    locals.var("PL-K", INT);
    locals.var("PL-PTR", "USAGE POINTER");
    let dec = call(module, &p.name, "DEC");
    let free = call(module, &p.name, "FREE");
    let mut b = body();
    // A packet with parameters takes the line's `!n` arguments (PB-ARGS).
    let mut args = String::new();
    for (i, x) in p.params.iter().enumerate() {
        let var = format!("PL-A{}", i);
        locals.var(&var, param_usage(&x.ty));
        b.line(format!("MOVE PB-ARG({}) TO {}", i + 1, var));
        args.push_str(&format!(" {}", var));
    }

    b.line("CALL \"PB-RINIT\"");
    set_version(&mut b, p);
    b.line(format!("IF PB-RC = 0 CALL {} USING P-REC{} END-IF", dec, args));
    b.open("IF PB-RC NOT = 0");
    disp(&mut b, "{\"ok\":false");
    b.line("MOVE 0 TO PB-A1");
    b.line("CALL \"PB-JERR\"");
    b.line("DISPLAY \"}\"");
    b.close("ELSE");
    b.push();
    let mut sets = Vec::new();
    settable(module, p, "", 0, 0, &mut sets);
    if !sets.is_empty() {
        b.open("PERFORM VARYING PL-K FROM 1 BY 1 UNTIL PL-K > PB-SETN");
        b.line("SET PL-PTR TO ADDRESS OF P-REC");
        b.open("EVALUATE PB-ST-PATH(PL-K)");
        for (path, off, ty) in &sets {
            b.open(format!("WHEN {}", cob_literal(path)));
            if *off > 0 {
                b.line(format!("SET PL-PTR UP BY {}", off));
            }
            let slot = point(&mut b, ty, "PL-PTR");
            match ty {
                ValueType::Int { width, signed } => {
                    let st = ValueType::Int { width: storage_for(*width), signed: *signed };
                    store_value(&mut b, "PB-ST-INT(PL-K)", &st, &slot.val);
                }
                ValueType::Str => {
                    b.line("IF LK-STR-P NOT = NULL FREE LK-STR-P END-IF");
                    b.line("SET PB-RP TO ADDRESS OF PB-ST-STR(PL-K)");
                    b.line("MOVE PB-ST-SLEN(PL-K) TO PB-RN");
                    b.line("CALL \"PB-DUP\"");
                    b.line("SET LK-STR-P TO PB-RP");
                    b.line("MOVE PB-RN TO LK-STR-N");
                }
                _ => b.line(format!("MOVE PB-ST-INT(PL-K) TO {}", slot.val)),
            }
            b.pop();
        }
        b.open("WHEN OTHER");
        b.line("CONTINUE");
        b.pop();
        b.close("END-EVALUATE");
        b.close("END-PERFORM");
    }
    disp(&mut b, "{\"ok\":true,\"value\":");
    b.line(format!("CALL {} USING P-REC", call(module, &p.name, "JSON")));
    b.line("CALL \"PB-WINIT\"");
    set_version(&mut b, p);
    b.line(format!("IF PB-RC = 0 CALL {} USING P-REC{} END-IF", call(module, &p.name, "ENC"), args));
    b.line("IF PB-RC = 0 CALL \"PB-WFINISH\" END-IF");
    b.open("IF PB-RC = 0");
    disp(&mut b, ",\"encoded\":");
    b.line("SET PB-WP TO ADDRESS OF PB-OUT");
    b.line("MOVE PB-WLEN TO PB-A1");
    b.line("CALL \"PB-JHEX\"");
    b.close("ELSE");
    b.push();
    b.line("MOVE 1 TO PB-A1");
    b.line("CALL \"PB-JERR\"");
    b.close("END-IF");
    b.line("DISPLAY \"}\"");
    b.close("END-IF");
    b.line(format!("CALL {} USING P-REC", free));
    let mut storage = format!("01 P-REC PIC X({}).\n", record_size(module, &p.name));
    if !p.params.is_empty() {
        // No stream helpers: the second line is `{}`.
        disp(&mut b, "{}");
        b.line("DISPLAY \"\"");
        b.line("GOBACK.");
        storage.push_str(ARGS_RECORD);
        return finish_run(out, module, p, &storage, &locals, b);
    }

    b.line("CALL \"PB-RINIT\"");
    set_version(&mut b, p);
    b.line(format!("IF PB-RC = 0 CALL {} USING P-REC END-IF", dec));
    b.open("EVALUATE PB-RC");
    b.open("WHEN 0");
    disp(&mut b, "{\"try\":\"done\",\"n\":");
    b.line("COMPUTE PB-X = (PB-POS + 7) / 8");
    b.line("CALL \"PB-JI\"");
    b.pop();
    b.open("WHEN 1");
    disp(&mut b, "{\"try\":\"incomplete\",\"n\":");
    b.line("COMPUTE PB-X = (PB-ENEED + 7) / 8");
    b.line("IF PB-X < 1 MOVE 1 TO PB-X END-IF");
    b.line("CALL \"PB-JI\"");
    b.pop();
    b.open("WHEN OTHER");
    disp(&mut b, "{\"try\":\"error\"");
    b.pop();
    b.close("END-EVALUATE");
    b.line(format!("CALL {} USING P-REC", free));
    if module.frame_length(p).is_some() {
        b.line(format!("CALL {}", call(module, &p.name, "FRAME")));
        b.open("EVALUATE PB-FRC");
        b.open("WHEN 0");
        disp(&mut b, ",\"frame\":");
        b.line("MOVE PB-FLEN TO PB-X");
        b.line("CALL \"PB-JI\"");
        b.pop();
        b.open("WHEN 1");
        disp(&mut b, ",\"frame\":null");
        b.pop();
        b.open("WHEN OTHER");
        disp(&mut b, ",\"frame\":\"error\"");
        b.pop();
        b.close("END-EVALUATE");
    }
    b.line("DISPLAY \"}\"");
    b.line("GOBACK.");
    finish_run(out, module, p, &storage, &locals, b);
}

fn finish_run(out: &mut Out, module: &Module, p: &Packet, storage: &str, locals: &Locals, b: Out) {
    let mut linkage = Out::new("   ");
    declare_pointed(&mut linkage);
    program(out, &format!("{}-RUN", prog(module, &p.name)), false, storage, locals, &linkage.buf, "", b);
}

/// The arguments the main program reads (`!n` options) for packets with
/// parameters; only files with such packets declare it.
pub const ARGS_RECORD: &str =
    "01 PB-ARGS EXTERNAL.\n   05 PB-ARGN BINARY-LONG SIGNED.\n   05 PB-ARG PIC S9(18) COMP-5 OCCURS 16.\n";

/// `-FRAME`: the size of the packet at the start of PB-IN from its header.
fn frame_program(out: &mut Out, module: &Module, p: &Packet) {
    let Some(f) = module.frame_length(p) else { return };
    let locals = Locals::default();
    let ev = Ev::new(module, p, Mode::Decode, &locals);
    let mut b = body();
    b.line("MOVE 1 TO PB-FRC");
    b.line("MOVE 0 TO PB-FLEN");
    if f.header_bytes > 0 {
        b.line(format!("IF PB-LEN < {} GOBACK END-IF", f.header_bytes));
    }
    b.line("MOVE LOW-VALUES TO P-REC");
    let bad = "IF PB-RC NOT = 0 MOVE 2 TO PB-FRC GOBACK END-IF";
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            let v = ev.eval(&mut b, c);
            b.open(format!("IF {} NOT = 0", v));
        }
        b.line("CALL \"PB-RINIT\"");
        b.line(format!("MOVE {} TO PB-X", h.offset_bits));
        b.line("CALL \"PB-SKIP\"");
        b.line(bad);
        match &h.container {
            Codec::Bytes { nbytes, endian } => {
                b.line(format!("MOVE {} TO PB-A1", nbytes));
                b.line(format!("MOVE {} TO PB-A2", little(endian)));
                b.line("MOVE 0 TO PB-A3");
                b.line("CALL \"PB-RUINT\"");
            }
            _ => {
                b.line(format!("MOVE {} TO PB-A1", h.container_bits));
                b.line("MOVE 0 TO PB-A3");
                b.line("CALL \"PB-RBITS\"");
            }
        }
        b.line(bad);
        b.line("MOVE PB-Z TO PB-X");
        b.line(format!("MOVE {} TO PB-A1", h.shift));
        b.line(format!("MOVE {} TO PB-A2", h.bits));
        b.line(format!("MOVE {} TO PB-A3", u32::from(h.signed)));
        b.line("CALL \"PB-EXTRACT\"");
        b.line(format!("MOVE PB-Z TO {}", field_name(h.member, &m.name)));
        if h.when.is_some() {
            b.close("END-IF");
        }
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            let v = ev.eval(&mut b, need);
            b.line(format!("IF PB-LEN < {} GOBACK END-IF", v));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            let v = ev.eval(&mut b, e);
            store_value(&mut b, &v, &m.ty, &field_name(c, &m.name));
        }
    }
    let total = ev.eval(&mut b, &f.total);
    b.line(format!("IF {} < 0 MOVE 2 TO PB-FRC GOBACK END-IF", total));
    b.line(format!("MOVE {} TO PB-FLEN", total));
    b.line("MOVE 0 TO PB-FRC");
    b.line("GOBACK.");

    let mut storage = Out::new("   ");
    declare_record(&mut storage, module, p, "P-REC");
    let mut linkage = Out::new("   ");
    declare_pointed(&mut linkage);
    program(out, &format!("{}-FRAME", prog(module, &p.name)), false, &storage.buf, &locals, &linkage.buf, "", b);
}

/// `-FRAME` for packets without parameters, and `-RUN`.
pub fn stream_programs(out: &mut Out, module: &Module, p: &Packet) {
    if p.params.is_empty() {
        frame_program(out, module, p);
    }
    run_program(out, module, p);
}
