//! COBOL encoder statements: each step writes from the record through the
//! runtime writer, range-checking values first.

use super::decode::{little, set_term};
use super::expr::{Ev, arm_test, call_args, call_packet, call_rt, fail, store_value};
use super::locals::{FLOAT, INT, Locals};
use super::naming::{Slot, arm_field, calc_local, cob_literal, elem_size, mark_local, named_slot, point};
use crate::generators::common::union::{mismatch_message, uses_selector};
use crate::generators::common::{Mode, Out, PREFIX_LEN, StepEmitter, mark_var};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Module, Packet, PacketRef, StrMode, TExpr, ValueType};

/// Fail with a range error unless `v` fits `width` bits.
fn range_check(out: &mut Out, v: &str, width: u32, signed: bool) {
    out.line(format!("MOVE {} TO PB-X", v));
    out.line(format!("MOVE {} TO PB-A1", width));
    call_rt(out, if signed { "PB-CI" } else { "PB-CU" });
}

/// Write `slot`, a value of `ty`, with `codec`.
pub fn write_value(ev: &Ev, out: &mut Out, codec: &Codec, ty: &ValueType, slot: &Slot) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        range_check(out, &slot.val, *width, *signed);
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("MOVE {} TO PB-X", slot.val));
            out.line(format!("MOVE {} TO PB-A1", nbytes));
            out.line(format!("MOVE {} TO PB-A2", little(endian)));
            call_rt(out, "PB-WUINT");
        }
        Codec::Bits { width } => {
            out.line(format!("MOVE {} TO PB-X", slot.val));
            out.line(format!("MOVE {} TO PB-A1", width));
            call_rt(out, "PB-WBITS");
        }
        Codec::Float { width, endian } => {
            out.line(format!("MOVE {} TO PB-X", slot.bits));
            out.line(format!("MOVE {} TO PB-A1", width / 8));
            out.line(format!("MOVE {} TO PB-A2", little(endian)));
            call_rt(out, "PB-WUINT");
        }
        Codec::Mac => {
            out.line(format!("SET PB-WP TO ADDRESS OF {}", slot.val));
            out.line("MOVE 6 TO PB-A1");
            call_rt(out, "PB-WRAW");
        }
        Codec::Varint(k) => {
            out.line(format!("MOVE {} TO PB-X", slot.val));
            out.line(format!("MOVE {} TO PB-A1", k.id()));
            call_rt(out, "PB-WVARINT");
        }
        Codec::Packet(r) => {
            let args = call_args(ev, out, r);
            call_packet(out, ev.module, &r.name, "ENC", &slot.val, &args);
        }
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

/// Write the `n` bytes at pointer `p`.
fn write_raw(out: &mut Out, p: &str, n: &str) {
    out.line(format!("SET PB-WP TO {}", p));
    out.line(format!("MOVE {} TO PB-A1", n));
    call_rt(out, "PB-WRAW");
}

/// Fail unless `n` (a length) equals `want`.
fn check_len(out: &mut Out, n: &str, want: &str) {
    out.line(format!("MOVE {} TO PB-X", n));
    out.line(format!("MOVE {} TO PB-Y", want));
    call_rt(out, "PB-CLEN");
}

pub struct Encoder<'a> {
    pub ev: Ev<'a>,
}

impl<'a> Encoder<'a> {
    pub fn new(module: &'a Module, packet: &'a Packet, locals: &'a Locals) -> Self {
        Encoder { ev: Ev::new(module, packet, Mode::Encode, locals) }
    }

    fn locals(&self) -> &Locals {
        self.ev.locals
    }

    fn field(&self, m: &Member) -> String {
        self.ev.scope.field(m)
    }

    fn index(&self, m: &Member) -> usize {
        self.packet().members.iter().position(|x| x.name == m.name).expect("member of its packet")
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.ev.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        let v = self.ev.eval(out, cond);
        out.open(format!("IF {} = 0", v));
        fail(out, 7, message);
        out.close("END-IF");
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        let lit = if field.is_empty() { "SPACES".to_string() } else { cob_literal(field) };
        out.line(format!("MOVE {} TO PB-FR-FLD(PB-DEPTH)", lit));
        out.line("MOVE -1 TO PB-FR-IDX(PB-DEPTH)");
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let base = self.field(m);
        let sel = self.locals().var("PL-SEL", INT);
        if uses_selector(arms) {
            let v = self.ev.eval(out, selector);
            out.line(format!("MOVE {} TO {}", v, sel));
        }
        out.open(format!("EVALUATE {}-K", base));
        for (k, arm) in arms.iter().enumerate() {
            out.open(format!("WHEN {}", k));
            if let Some(test) = arm_test(arm, arms, &sel) {
                out.open(format!("IF NOT {}", test));
                fail(out, 6, &mismatch_message(&m.name, arm));
                out.close("END-IF");
            }
            let af = arm_field(&base, k);
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        let n = self.ev.eval(out, e);
                        check_len(out, &format!("{}-N", af), &n);
                    }
                    write_raw(out, &format!("{}-P", af), &format!("{}-N", af));
                }
                (Some(ty), Some(codec), None) => write_value(&self.ev, out, codec, ty, &named_slot(&af)),
                _ => {}
            }
            out.pop();
        }
        out.open("WHEN OTHER");
        fail(out, 2, &format!("`{}` holds no known arm", m.name));
        out.pop();
        out.close("END-EVALUATE");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let off = self.ev.eval(out, offset);
        out.line(format!("MOVE {} TO PB-X", if root { "0" } else { "PL-START" }));
        out.line(format!("MOVE {} TO PB-Y", off));
        out.line(format!("MOVE {} TO PB-A1", u32::from(root)));
        call_rt(out, "PB-WSUB");
        let args = call_args(&self.ev, out, target);
        call_packet(out, self.ev.module, &target.name, "ENC", &self.field(m), &args);
        call_rt(out, "PB-WPLACE");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            let w = self.locals().var(format!("PL-WIN{}", id), INT);
            let z = self.locals().var(format!("PL-WSZ{}", id), INT);
            out.line(format!("MOVE PB-WPOS TO {}", w));
            let v = self.ev.eval(out, e);
            out.line(format!("MOVE {} TO {}", v, z));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("MOVE PL-WIN{} TO PB-X", id));
            out.line(format!("MOVE PL-WSZ{} TO PB-Y", id));
            out.line(format!("MOVE {} TO PB-A1", u32::from(exact)));
            call_rt(out, "PB-WENDWIN");
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals().var(mark_local(&mark_var(mark)), INT);
        out.line(format!("MOVE PB-WPOS TO {}", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        let name = calc_local(self.index(m));
        let v = self.ev.eval(out, value);
        if m.is_derived() {
            self.locals().var(&name, INT);
            out.line(format!("MOVE {} TO {}", v, name));
        } else {
            let usage = match m.ty {
                ValueType::Float { width: 32 } => "FLOAT-SHORT",
                ValueType::Float { .. } => FLOAT,
                _ => INT,
            };
            self.locals().var(&name, usage);
            store_value(out, &v, &m.ty, &name);
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = calc_local(self.index(m));
        if let ValueType::Int { width, signed } = &m.ty {
            range_check(out, &v, *width, *signed);
        }
        out.line(format!("MOVE {} TO PB-X", v));
        if let Some(at) = at {
            out.line(format!("MOVE {} TO PB-Y", mark_local(&mark_var(at))));
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, _) => {
                out.line(format!("MOVE {} TO PB-A1", nbytes));
                out.line(format!("MOVE {} TO PB-A2", little(endian)));
                call_rt(out, if at.is_some() { "PB-WPATCHU" } else { "PB-WUINT" });
            }
            (Codec::Bits { width }, _) => {
                out.line(format!("MOVE {} TO PB-A1", width));
                call_rt(out, if at.is_some() { "PB-WPATCHB" } else { "PB-WBITS" });
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), _) => {
                out.line(format!("MOVE {} TO PB-A1", k.id()));
                call_rt(out, "PB-WVARINT");
            }
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line("MOVE PL-START TO PB-X");
        out.line(format!("MOVE {} TO PB-A1", bytes * 8));
        call_rt(out, "PB-WALIGN");
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let f = self.field(m);
        let sp = self.locals().var("PL-SP", "USAGE POINTER");
        let sn = self.locals().var("PL-SN", INT);
        out.line(format!("SET PB-SP TO {}-P", f));
        out.line(format!("MOVE {}-N TO PB-SN", f));
        if m.encoding != crate::ir::TextEncoding::Utf8 {
            out.line(format!("MOVE {} TO PB-A3", m.encoding.id()));
            call_rt(out, "PB-TOTEXT");
        }
        out.line(format!("SET {} TO PB-SP", sp));
        out.line(format!("MOVE PB-SN TO {}", sn));
        match (mode, array) {
            (StrMode::CString, _) => {
                call_rt(out, "PB-CNONUL");
                write_raw(out, &sp, &sn);
                set_term(out, &[0]);
                call_rt(out, "PB-WTERM");
            }
            (StrMode::Terminated { term, .. }, _) => {
                set_term(out, term);
                call_rt(out, "PB-CNOTERM");
                write_raw(out, &sp, &sn);
                call_rt(out, "PB-WTERM");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                range_check(out, &sn, *width, false);
                write_value(&self.ev, out, prefix, &PREFIX_LEN, &Slot { val: sn.clone(), bits: sn.clone() });
                write_raw(out, &sp, &sn);
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                let len = self.locals().var("PL-LEN", INT);
                let v = self.ev.eval(out, e);
                out.line(format!("MOVE {} TO {}", v, len));
                out.line(format!("MOVE {} TO PB-X", sn));
                out.line(format!("MOVE {} TO PB-Y", len));
                call_rt(out, "PB-CFITS");
                write_raw(out, &sp, &sn);
                out.line(format!("COMPUTE PB-X = ({} - {}) * 8", len, sn));
                call_rt(out, "PB-WZERO");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                let v = self.ev.eval(out, e);
                check_len(out, &sn, &v);
                write_raw(out, &sp, &sn);
            }
            _ => write_raw(out, &sp, &sn),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => {
                out.line(format!("MOVE {} TO PB-X", bits));
                call_rt(out, "PB-WZERO");
            }
            Some(Count::Expr(e)) => {
                let n = self.ev.eval(out, e);
                out.line(format!("MOVE {} TO PB-X", n));
                out.line("IF PB-X < 0 MOVE 0 TO PB-X END-IF");
                out.line(format!("COMPUTE PB-X = PB-X * {}", bits));
                call_rt(out, "PB-WZERO");
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        let v = self.ev.eval(out, cond);
        out.open(format!("IF {} NOT = 0", v));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("END-IF");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.ev.scope.packet.version_bounds();
        out.line(format!("MOVE {} TO PB-A1", self.field(m)));
        out.line(format!("MOVE {} TO PB-A2", min));
        out.line(format!("MOVE {} TO PB-A3", latest));
        call_rt(out, "PB-ADOPTVER");
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_value(&self.ev, out, codec, ty, &named_slot(&self.field(m)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let f = self.field(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            let v = self.ev.eval(out, e);
            check_len(out, &format!("{}-N", f), &v);
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("SET PB-SP TO {}-P", f));
            out.line(format!("MOVE {}-N TO PB-SN", f));
            set_term(out, term);
            call_rt(out, "PB-CNOTERM");
            write_raw(out, &format!("{}-P", f), &format!("{}-N", f));
            call_rt(out, "PB-WTERM");
        } else if ty.is_byte() {
            write_raw(out, &format!("{}-P", f), &format!("{}-N", f));
        } else {
            let esz = elem_size(self.ev.module, ty);
            self.locals().var("PL-I", INT);
            self.locals().var("PL-EP", "USAGE POINTER");
            self.locals().var("PL-OFF", INT);
            out.open(format!("PERFORM VARYING PL-I FROM 0 BY 1 UNTIL PL-I >= {}-N", f));
            out.line("MOVE PL-I TO PB-FR-IDX(PB-DEPTH)");
            out.line(format!("SET PL-EP TO {}-P", f));
            out.line(format!("COMPUTE PL-OFF = PL-I * {}", esz));
            out.line("SET PL-EP UP BY PL-OFF");
            let slot = point(out, ty, "PL-EP");
            write_value(&self.ev, out, codec, ty, &slot);
            out.close("END-PERFORM");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let bf = self.locals().var("PL-BF", INT);
        out.line(format!("MOVE 0 TO {}", bf));
        for part in parts {
            let place = self.field(self.ev.scope.member(part.member));
            range_check(out, &place, part.width, part.signed);
            out.line(format!("MOVE {} TO PB-X", bf));
            out.line(format!("MOVE {} TO PB-Y", place));
            out.line(format!("MOVE {} TO PB-A1", part.shift));
            out.line(format!("MOVE {} TO PB-A2", part.width));
            out.line("CALL \"PB-INSERT\"");
            out.line(format!("MOVE PB-Z TO {}", bf));
        }
        out.line(format!("MOVE {} TO PB-X", bf));
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("MOVE {} TO PB-A1", nbytes));
                out.line(format!("MOVE {} TO PB-A2", little(endian)));
                call_rt(out, "PB-WUINT");
            }
            _ => {
                out.line(format!("MOVE {} TO PB-A1", container_width));
                call_rt(out, "PB-WBITS");
            }
        }
    }
}
