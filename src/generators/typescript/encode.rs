//! TypeScript encoder statements.

use super::decode::{arm_test, call_args};
use super::expr::store_value;
use super::locals::Locals;
use super::naming::{TypeScript, byte_list, ident, is_big, member_type};
use crate::generators::common::union::{mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

fn write_elem(scope: &Scope<'_, TypeScript>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    match ty {
        ValueType::Int { width, signed: true } => out.line(format!("pb_w.checkI({}, {});", v, width)),
        ValueType::Int { width, signed: false } => out.line(format!("pb_w.checkU({}, {});", v, width)),
        ValueType::Mac => out.line(format!("pb_w.checkMac({});", v)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pb_w.writeUint({}, {}, {});", v, nbytes, TypeScript::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pb_w.writeBits({}, {});", v, width)),
        Codec::Float { width, endian } => {
            let f = if *width == 32 { "writeF32" } else { "writeF64" };
            out.line(format!("pb_w.{}({}, {});", f, v, TypeScript::little(endian)));
        }
        Codec::Mac => out.line(format!("pb_w.writeBytes({});", v)),
        Codec::Varint(k) => out.line(format!("pb_w.writeVarint({}, {});", k.id(), v)),
        Codec::Packet(r) => out.line(format!("{}.encodeTo(pb_w{});", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, TypeScript>,
    pub locals: Locals,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode), locals: Locals::default() }
    }

    fn mark_local(&self, mark: Mark) -> String {
        let v = mark_var(mark);
        self.locals.declare(&v, "number", "0");
        v
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if (!{}) throw pb_w.error(PbError.CONSTRAINT, {});",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_w.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        out.open("{");
        if uses_selector(arms) {
            out.line(format!("const pb_sel = {};", self.scope.expr(selector)));
        }
        out.line(format!("const pb_u = p.{};", ident(&m.name)));
        for (i, arm) in arms.iter().enumerate() {
            out.open(format!("{}if (pb_u.kind === \"{}\") {{", if i == 0 { "" } else { "} else " }, arm.name));
            if let Some(test) = arm_test(arm, arms) {
                out.line(format!(
                    "if (!{}) throw pb_w.error(PbError.MISMATCH, {});",
                    test,
                    string_literal(&mismatch_message(&m.name, arm))
                ));
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pb_w.checkLen(pb_u.value.length, {});", self.scope.expr(e)));
                    }
                    out.line("pb_w.writeBytes(pb_u.value);");
                }
                (Some(ty), Some(codec), None) => write_elem(&self.scope, out, codec, ty, "pb_u.value"),
                _ => {}
            }
            out.pop();
        }
        out.open("} else {");
        out.line(format!(
            "throw pb_w.error(PbError.INVALID, {});",
            string_literal(&format!("`{}` holds no known arm", m.name))
        ));
        out.close("}");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            self.locals.declare(&format!("pb_win{}", id), "number", "0");
            self.locals.declare(&format!("pb_wsz{}", id), "bigint", "0n");
            out.line(format!("pb_win{} = pb_w.positionBits();", id));
            out.line(format!("pb_wsz{} = {};", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pb_w.endWindow(pb_win{}, pb_wsz{}, {});", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pb_w.positionBits();", self.mark_local(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        let name = format!("pbc_{}", m.name);
        if m.is_derived() {
            self.locals.declare(&name, "bigint", "0n");
            out.line(format!("{} = {};", name, self.scope.expr(value)));
        } else {
            let init = if is_big(&m.ty) { "0n" } else { "0" };
            self.locals.declare(&name, &member_type(m), init);
            out.line(format!("{} = {};", name, store_value(self.scope.expr(value), &m.ty)));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            let f = if *signed { "checkI" } else { "checkU" };
            out.line(format!("pb_w.{}({}, {});", f, v, width));
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pb_w.writeUint({}, {}, {});", v, nbytes, TypeScript::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => out.line(format!(
                "pb_w.patchUint({}, {}, {}, {});",
                mark_var(at),
                v,
                nbytes,
                TypeScript::little(endian)
            )),
            (Codec::Bits { width }, None) => out.line(format!("pb_w.writeBits({}, {});", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pb_w.patchBits({}, {}, {});", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("pb_w.writeVarint({}, {});", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        out.open("{");
        out.line(format!("const pb_s = pb_w.sub({}, {}, {});", from, self.scope.expr(offset), root));
        out.line(format!("p.{}.encodeTo(pb_s{});", ident(&m.name), call_args(&self.scope, target)));
        out.line("pb_w.place(pb_s);");
        out.close("}");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_w.writeZeroBits(pbPad(pb_w.positionBits() - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("const pb_b = pb_w.utf8Bytes(p.{});", ident(&m.name)));
        } else {
            out.line(format!("const pb_b = pb_w.textBytes(p.{}, {});", ident(&m.name), m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pb_w.checkNoNul(pb_b);");
                out.line("pb_w.writeBytes(pb_b);");
                out.line("pb_w.writeUint(0, 1, false);");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("pb_w.checkNoTerm(pb_b, {});", byte_list(term)));
                out.line("pb_w.writeBytes(pb_b);");
                out.line(format!("pb_w.writeBytes({});", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pb_w.checkU(pb_b.length, {});", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "pb_b.length");
                out.line("pb_w.writeBytes(pb_b);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("const pb_n = {};", self.scope.expr(e)));
                out.line("pb_w.checkFits(pb_b.length, pb_n);");
                out.line("pb_w.writeBytes(pb_b);");
                out.line("pb_w.writeZeroBits((Number(pb_n) - pb_b.length) * 8);");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pb_w.checkLen(pb_b.length, {});", self.scope.expr(e)));
                out.line("pb_w.writeBytes(pb_b);");
            }
            _ => out.line("pb_w.writeBytes(pb_b);"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_w.writeZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_w.writeZeroBits(Number(pbMax({}, 0n)) * {});", self.scope.expr(e), bits))
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if ({}) {{", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("}");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("pb_w.adoptVersion({}, {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &format!("p.{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pb_w.checkLen({}.length, {});", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("pb_w.checkNoTerm({}, {});", place, byte_list(term)));
            out.line(format!("pb_w.writeBytes({});", place));
            out.line(format!("pb_w.writeBytes({});", byte_list(term)));
        } else if ty.is_byte() {
            out.line(format!("pb_w.writeBytes({});", place));
        } else {
            out.open(format!("for (let pb_i = 0; pb_i < {}.length; pb_i++) {{", place));
            out.line("pb_w.atIndex(pb_i);");
            out.line(format!("const pb_v = {}[pb_i];", place));
            write_elem(&self.scope, out, codec, ty, "pb_v");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let big = container_width > 32;
        out.open("{");
        out.line(format!("let pb_c = {};", if big { "0n" } else { "0" }));
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", ident(&m.name));
            let f = if part.signed { "checkI" } else { "checkU" };
            out.line(format!("pb_w.{}({}, {});", f, place, part.width));
            let bits = match (big, is_big(&m.ty)) {
                (true, true) => format!("({} & 0x{:x}n)", place, mask(part.width)),
                (true, false) => format!("(BigInt({}) & 0x{:x}n)", place, mask(part.width)),
                (false, true) => format!("Number(BigInt.asUintN({}, {}))", part.width, place),
                (false, false) => format!("({} & 0x{:x})", place, mask(part.width)),
            };
            if big {
                out.line(format!("pb_c |= {} << {}n;", bits, part.shift));
            } else {
                out.line(format!("pb_c |= {} << {};", bits, part.shift));
            }
        }
        let v = if big { "pb_c" } else { "pb_c >>> 0" };
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pb_w.writeUint({}, {}, {});", v, nbytes, TypeScript::little(endian)))
            }
            _ => out.line(format!("pb_w.writeBits({}, {});", v, container_width)),
        }
        out.close("}");
    }
}
