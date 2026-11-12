//! COBOL decoder statements: each step reads into the record through the
//! runtime programs and checks `PB-RC` after every one that can fail.

use super::expr::{Ev, arm_test, call_args, call_packet, call_rt, fail, store_value};
use super::locals::{FLOAT, INT, Locals};
use super::naming::{Slot, arm_field, cob_literal, elem_size, field_name, hex_literal, mark_local, named_slot, point};
use crate::ast::Endianness;
use crate::generators::common::{Mode, Out, PREFIX_LEN, StepEmitter, mark_var};
use crate::ir::{
    Arm, BitPart, Codec, Count, Mark, Member, Module, Packet, PacketRef, StrMode, TExpr, ValueType, storage_for,
};

pub fn little(e: &Endianness) -> u32 {
    u32::from(*e == Endianness::Le)
}

/// Whether the decoder allocates member `mi`'s bytes (rather than pointing
/// into the input): always, unless zero-copy and the bytes are read in one
/// piece.
pub fn owns_bytes(p: &Packet, mi: usize, zero_copy: bool) -> bool {
    !zero_copy
        || p.field_steps(mi)
            .iter()
            .any(|&s| matches!(&p.steps[s], crate::ir::Step::Field { array: Some(Count::Until(_)), .. }))
}

/// `MOVE <term> TO PB-TERM` and its length.
pub fn set_term(out: &mut Out, term: &[u8]) {
    out.line(format!("MOVE {} TO PB-TERM", hex_literal(term)));
    out.line(format!("MOVE {} TO PB-TLEN", term.len()));
}

/// Read one value of `ty` with `codec` into `slot`.
pub fn read_into(ev: &Ev, out: &mut Out, codec: &Codec, ty: &ValueType, slot: &Slot) {
    let sext = match ty {
        ValueType::Int { width, signed: true } => *width,
        _ => 0,
    };
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("MOVE {} TO PB-A1", nbytes));
            out.line(format!("MOVE {} TO PB-A2", little(endian)));
            out.line(format!("MOVE {} TO PB-A3", sext));
            call_rt(out, "PB-RUINT");
            out.line(format!("MOVE PB-Z TO {}", slot.val));
        }
        Codec::Bits { width } => {
            out.line(format!("MOVE {} TO PB-A1", width));
            out.line(format!("MOVE {} TO PB-A3", sext));
            call_rt(out, "PB-RBITS");
            out.line(format!("MOVE PB-Z TO {}", slot.val));
        }
        Codec::Varint(k) => {
            out.line(format!("MOVE {} TO PB-A1", k.id()));
            call_rt(out, "PB-RVARINT");
            match ty {
                ValueType::Int { width, signed: true } if *width < 64 => {
                    store_value(out, "PB-Z", ty, &slot.val);
                }
                ValueType::Int { width, signed: false } if storage_for(*width) < 64 => {
                    let st = ValueType::Int { width: storage_for(*width), signed: false };
                    store_value(out, "PB-Z", &st, &slot.val);
                }
                _ => out.line(format!("MOVE PB-Z TO {}", slot.val)),
            }
        }
        Codec::Float { width, endian } => {
            out.line(format!("MOVE {} TO PB-A1", width / 8));
            out.line(format!("MOVE {} TO PB-A2", little(endian)));
            out.line("MOVE 0 TO PB-A3");
            call_rt(out, "PB-RUINT");
            out.line(format!("MOVE PB-Z TO {}", slot.bits));
        }
        Codec::Mac => {
            out.line("MOVE 6 TO PB-X");
            call_rt(out, "PB-RREF");
            out.line("SET ADDRESS OF LK-SRC TO PB-RP");
            out.line(format!("MOVE LK-SRC(1:6) TO {}", slot.val));
        }
        Codec::Packet(r) => {
            let args = call_args(ev, out, r);
            call_packet(out, ev.module, &r.name, "DEC", &slot.val, &args);
        }
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    }
}

/// `PB-RP`/`PB-RN` into the buffer `base` (`-P`/`-N`), copied unless the
/// decoder points into the input.
fn keep_bytes(out: &mut Out, base: &str, copy: bool) {
    if copy {
        call_rt(out, "PB-DUP");
    }
    out.line(format!("SET {}-P TO PB-RP", base));
    out.line(format!("MOVE PB-RN TO {}-N", base));
}

pub struct Decoder<'a> {
    pub ev: Ev<'a>,
    zero_copy: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(module: &'a Module, packet: &'a Packet, locals: &'a Locals, zero_copy: bool) -> Self {
        Decoder { ev: Ev::new(module, packet, Mode::Decode, locals), zero_copy }
    }

    fn locals(&self) -> &Locals {
        self.ev.locals
    }

    fn field(&self, m: &Member) -> String {
        self.ev.scope.field(m)
    }

    /// `PB-RP`/`PB-RN` := the next `count` bytes (`PB-COUNT` checks it).
    fn read_counted(&self, out: &mut Out, count: &str) {
        out.line(format!("MOVE {} TO PB-X", count));
        out.line("MOVE 8 TO PB-A1");
        call_rt(out, "PB-COUNT");
        out.line("MOVE PB-Z TO PB-X");
        call_rt(out, "PB-RREF");
    }

    /// `PB-RP`/`PB-RN` := every whole byte left.
    fn read_rest(&self, out: &mut Out) {
        out.line("COMPUTE PB-X = (PB-LIMIT - PB-POS) / 8");
        call_rt(out, "PB-RREF");
    }

    /// Decode arm `k` of union field `base`.
    fn arm(&self, out: &mut Out, base: &str, k: usize, arm: &Arm) {
        let af = arm_field(base, k);
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => {}
            (Some(_), _, Some(Count::Expr(e))) => {
                let n = self.ev.eval(out, e);
                self.read_counted(out, &n);
                keep_bytes(out, &af, !self.zero_copy);
            }
            (Some(_), _, Some(_)) => {
                self.read_rest(out);
                keep_bytes(out, &af, !self.zero_copy);
            }
            (Some(ty), Some(codec), None) => read_into(&self.ev, out, codec, ty, &named_slot(&af)),
            _ => {}
        }
    }

    /// Point `PL-EP` at element `index` of the array `base` (`esz` bytes each).
    fn elem_ptr(&self, out: &mut Out, base: &str, index: &str, esz: u64) {
        self.locals().var("PL-EP", "USAGE POINTER");
        self.locals().var("PL-OFF", INT);
        out.line(format!("SET PL-EP TO {}-P", base));
        out.line(format!("COMPUTE PL-OFF = ({}) * {}", index, esz));
        out.line("SET PL-EP UP BY PL-OFF");
    }

    /// The local an `until` condition reads, from the element at `PL-EP`.
    fn set_last(&self, out: &mut Out, ty: &ValueType) {
        match ty {
            ValueType::Packet(_) | ValueType::Union(_) | ValueType::Mac | ValueType::Str => {
                self.locals().var("PL-LASTP", "USAGE POINTER");
                out.line("SET PL-LASTP TO PL-EP");
            }
            ValueType::Float { .. } => {
                self.locals().var("PL-LASTF", FLOAT);
                let slot = point(out, ty, "PL-EP");
                out.line(format!("MOVE {} TO PL-LASTF", slot.val));
            }
            ValueType::Int { .. } => {
                self.locals().var("PL-LASTI", INT);
                let slot = point(out, ty, "PL-EP");
                out.line(format!("MOVE {} TO PL-LASTI", slot.val));
            }
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.ev.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        let v = self.ev.eval(out, cond);
        out.open(format!("IF {} = 0", v));
        fail(out, 7, message);
        out.close("END-IF");
    }

    fn locate(&self, out: &mut Out, field: &str) {
        let lit = if field.is_empty() { "SPACES".to_string() } else { cob_literal(field) };
        out.line(format!("MOVE {} TO PB-FR-FLD(PB-DEPTH)", lit));
        out.line("MOVE -1 TO PB-FR-IDX(PB-DEPTH)");
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let base = self.field(m);
        let sel = self.locals().var("PL-SEL", INT);
        let v = self.ev.eval(out, selector);
        out.line(format!("MOVE {} TO {}", v, sel));
        out.open("EVALUATE TRUE");
        for (k, arm) in arms.iter().enumerate().filter(|(_, a)| !a.default) {
            let test = arm_test(arm, arms, &sel).unwrap_or_else(|| "TRUE".into());
            out.open(format!("WHEN {}", test));
            out.line(format!("MOVE {} TO {}-K", k, base));
            self.arm(out, &base, k, arm);
            out.pop();
        }
        out.open("WHEN OTHER");
        match arms.iter().position(|a| a.default) {
            Some(k) => {
                out.line(format!("MOVE {} TO {}-K", k, base));
                self.arm(out, &base, k, &arms[k]);
            }
            None => {
                let ed = self.locals().var("PL-ED", "PIC -(19)9");
                out.line(format!("MOVE {} TO {}", sel, ed));
                out.line("MOVE SPACES TO PB-MSG");
                out.line(format!(
                    "STRING {} FUNCTION TRIM({}) DELIMITED BY SIZE INTO PB-MSG END-STRING",
                    cob_literal(&format!("no arm of `{}` for ", m.name)),
                    ed
                ));
                out.line("MOVE 2 TO PB-A1");
                out.line("MOVE 0 TO PB-A2");
                out.line("CALL \"PB-FAIL\"");
                out.line("GOBACK");
            }
        }
        out.pop();
        out.close("END-EVALUATE");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.ev.eval(out, e)).unwrap_or_else(|| "0".into());
        let w = self.locals().var(format!("PL-WIN{}", id), INT);
        out.line(format!("MOVE {} TO PB-X", size));
        call_rt(out, "PB-PUSHLIM");
        out.line(format!("MOVE PB-Z TO {}", w));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("MOVE PL-WIN{} TO PB-X", id));
        out.line(format!("MOVE {} TO PB-A1", u32::from(exact)));
        call_rt(out, "PB-POPLIM");
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals().var(mark_local(&mark_var(mark)), INT);
        out.line(format!("MOVE PB-POS TO {}", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        let v = self.ev.eval(out, value);
        out.open(format!("IF {} NOT = {}", self.field(m), v));
        fail(out, 6, &format!("`{}` does not match the value computed from the data", m.name));
        out.close("END-IF");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let off = self.ev.eval(out, offset);
        for j in ["PL-J1", "PL-J2", "PL-J3"] {
            self.locals().var(j, INT);
        }
        out.line(format!("MOVE {} TO PB-X", if root { "0" } else { "PL-START" }));
        out.line(format!("MOVE {} TO PB-Y", off));
        call_rt(out, "PB-JUMP");
        out.line("MOVE PB-Z TO PL-J1");
        out.line("MOVE PB-Z2 TO PL-J2");
        out.line("MOVE PB-Z3 TO PL-J3");
        let args = call_args(&self.ev, out, target);
        call_packet(out, self.ev.module, &target.name, "DEC", &self.field(m), &args);
        out.line("MOVE PL-J1 TO PB-POS");
        out.line("MOVE PL-J2 TO PB-LIMIT");
        out.line("MOVE PL-J3 TO PB-WINS");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line("MOVE PL-START TO PB-X");
        out.line(format!("MOVE {} TO PB-A1", bytes * 8));
        call_rt(out, "PB-RALIGN");
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        let v = self.ev.eval(out, e);
        store_value(out, &v, &m.ty, &self.field(m));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        match (mode, array) {
            (StrMode::CString, _) => {
                set_term(out, &[0]);
                out.line("MOVE 0 TO PB-A2");
                call_rt(out, "PB-RUNTIL");
            }
            (StrMode::Terminated { term, optional }, _) => {
                set_term(out, term);
                out.line(format!("MOVE {} TO PB-A2", u32::from(*optional)));
                call_rt(out, "PB-RUNTIL");
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                let t = self.locals().int();
                read_into(&self.ev, out, prefix, &PREFIX_LEN, &Slot { val: t.clone(), bits: t.clone() });
                self.read_counted(out, &t);
            }
            (_, Some(Count::Expr(e))) => {
                let n = self.ev.eval(out, e);
                self.read_counted(out, &n);
            }
            _ => self.read_rest(out),
        }
        let f = self.field(m);
        out.line(format!("MOVE {} TO PB-A2", u32::from(*mode == StrMode::Padded)));
        out.line(format!("MOVE {} TO PB-A3", m.encoding.id()));
        call_rt(out, "PB-CONVTEXT");
        out.line(format!("SET {}-P TO PB-SP", f));
        out.line(format!("MOVE PB-SN TO {}-N", f));
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => {
                out.line(format!("MOVE {} TO PB-X", bits));
                call_rt(out, "PB-SKIP");
            }
            Some(Count::Expr(e)) => {
                let n = self.ev.eval(out, e);
                out.line(format!("MOVE {} TO PB-X", n));
                out.line(format!("MOVE {} TO PB-A1", bits));
                call_rt(out, "PB-COUNT");
                out.line(format!("COMPUTE PB-X = PB-Z * {}", bits));
                call_rt(out, "PB-SKIP");
            }
            Some(Count::Remaining) => {
                out.line("COMPUTE PB-X = PB-LIMIT - PB-POS");
                call_rt(out, "PB-SKIP");
            }
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
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
        call_rt(out, "PB-SETVER");
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        read_into(&self.ev, out, codec, ty, &named_slot(&self.field(m)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let f = self.field(m);
        let module = self.ev.module;
        let esz = elem_size(module, ty);
        let mi = self.packet().members.iter().position(|x| x.name == m.name).expect("member");
        let copy = owns_bytes(self.packet(), mi, self.zero_copy);
        match count {
            Count::Expr(e) => {
                let n = self.ev.eval(out, e);
                out.line(format!("MOVE {} TO PB-X", n));
                out.line(format!("MOVE {} TO PB-A1", codec.min_elem_bits()));
                call_rt(out, "PB-COUNT");
                if ty.is_byte() {
                    out.line("MOVE PB-Z TO PB-X");
                    call_rt(out, "PB-RREF");
                    keep_bytes(out, &f, copy);
                } else {
                    self.locals().var("PL-I", INT);
                    out.line(format!("MOVE PB-Z TO {}-N", f));
                    out.line("MOVE PB-Z TO PB-A1");
                    out.line(format!("MOVE {} TO PB-A2", esz));
                    call_rt(out, "PB-ALLOC");
                    out.line(format!("SET {}-P TO PB-RP", f));
                    out.open(format!("PERFORM VARYING PL-I FROM 0 BY 1 UNTIL PL-I >= {}-N", f));
                    out.line("MOVE PL-I TO PB-FR-IDX(PB-DEPTH)");
                    self.elem_ptr(out, &f, "PL-I", esz);
                    let slot = point(out, ty, "PL-EP");
                    read_into(&self.ev, out, codec, ty, &slot);
                    out.close("END-PERFORM");
                }
            }
            Count::Terminated { term, optional } => {
                set_term(out, term);
                out.line(format!("MOVE {} TO PB-A2", u32::from(*optional)));
                call_rt(out, "PB-RUNTIL");
                keep_bytes(out, &f, copy);
            }
            Count::Remaining if ty.is_byte() => {
                self.read_rest(out);
                keep_bytes(out, &f, copy);
            }
            Count::Until(_) | Count::Remaining => {
                let cap = self.locals().var("PL-CAP", INT);
                out.line(format!("SET {}-P TO NULL", f));
                out.line(format!("MOVE 0 TO {}-N", f));
                out.line(format!("MOVE 0 TO {}", cap));
                out.open("PERFORM UNTIL PB-LIMIT - PB-POS <= 0");
                out.line(format!("MOVE {}-N TO PB-FR-IDX(PB-DEPTH)", f));
                out.line(format!("SET PB-GP TO {}-P", f));
                out.line(format!("MOVE {} TO PB-GCAP", cap));
                out.line(format!("COMPUTE PB-A1 = {}-N + 1", f));
                out.line(format!("MOVE {} TO PB-A2", esz));
                call_rt(out, "PB-GROW");
                out.line(format!("SET {}-P TO PB-GP", f));
                out.line(format!("MOVE PB-GCAP TO {}", cap));
                self.elem_ptr(out, &f, &format!("{}-N", f), esz);
                let slot = point(out, ty, "PL-EP");
                read_into(&self.ev, out, codec, ty, &slot);
                out.line(format!("ADD 1 TO {}-N", f));
                if let Count::Until(cond) = count {
                    self.elem_ptr(out, &f, &format!("{}-N - 1", f), esz);
                    self.set_last(out, ty);
                    let v = self.ev.eval(out, cond);
                    out.line(format!("IF {} NOT = 0 EXIT PERFORM END-IF", v));
                }
                out.close("END-PERFORM");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let bf = self.locals().var("PL-BF", INT);
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("MOVE {} TO PB-A1", nbytes));
                out.line(format!("MOVE {} TO PB-A2", little(endian)));
                out.line("MOVE 0 TO PB-A3");
                call_rt(out, "PB-RUINT");
            }
            _ => {
                out.line(format!("MOVE {} TO PB-A1", container_width));
                out.line("MOVE 0 TO PB-A3");
                call_rt(out, "PB-RBITS");
            }
        }
        out.line(format!("MOVE PB-Z TO {}", bf));
        for part in parts {
            let m = self.ev.scope.member(part.member);
            out.line(format!("MOVE {} TO PB-X", bf));
            out.line(format!("MOVE {} TO PB-A1", part.shift));
            out.line(format!("MOVE {} TO PB-A2", part.width));
            out.line(format!("MOVE {} TO PB-A3", u32::from(part.signed)));
            out.line("CALL \"PB-EXTRACT\"");
            out.line(format!("MOVE PB-Z TO {}", field_name(part.member, &m.name)));
        }
    }
}
