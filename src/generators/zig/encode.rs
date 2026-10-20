//! Zig encoder statements. Range checks are not needed: exact-width fields
//! cannot hold out-of-range values.

use super::decode::byte_list;
use super::expr::store_value;
use super::naming::{Zig, ident, scalar_type};
use crate::generators::common::union::{ZIG_LOGIC, arm_test, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, TextEncoding, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, v: &str) {
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("try pb_w.writeUint(pbToBits({}), {}, {});", v, nbytes, Zig::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("try pb_w.writeBits(pbToBits({}), {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("try pb_w.writeUint(@as(u32, @bitCast({})), 4, {});", v, Zig::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("try pb_w.writeUint(@as(u64, @bitCast({})), 8, {});", v, Zig::little(endian)))
        }
        Codec::Mac => out.line(format!("try pb_w.writeBytes(&{});", v)),
        Codec::Varint(k) => out.line(format!("try pb_w.writeVarint({}, pbToBits({}));", k.id(), v)),
        Codec::Packet(_) => out.line(format!("try {}.encodeTo(pb_w);", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Zig>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }
}

impl Encoder<'_> {
    /// A terminated string, or one in an encoding other than UTF-8.
    fn encoded_string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let s = format!("p.{}", ident(&m.name));
        let enc = m.encoding.id();
        let write = format!("try pb_w.writeText({}, {});", s, enc);
        out.open("{");
        out.line(format!("const pb_sz = try pb_w.textSize({}, {});", s, enc));
        match (mode, array) {
            (StrMode::CString | StrMode::Terminated { .. }, _) => {
                let term = match mode {
                    StrMode::Terminated { term, .. } => term.clone(),
                    _ => vec![0],
                };
                out.line("_ = pb_sz;");
                out.line("const pb_from = pb_w.positionBits();");
                out.line(write);
                out.line(format!("try pb_w.checkNoTerm(pb_from, {});", byte_list(&term)));
                out.line(format!("try pb_w.writeBytes({});", byte_list(&term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("try pb_w.checkPrefix(pb_sz, {});", width));
                write_elem(out, prefix, "@as(u64, pb_sz)");
                out.line(write);
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("const pb_n = {};", self.scope.expr(e)));
                out.line("try pb_w.checkFits(pb_sz, pb_n);");
                out.line(write);
                out.line("try pb_w.writeZeroBits((pb_n - @as(i64, @intCast(pb_sz))) * 8);");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("try pb_w.checkLen(pb_sz, {});", self.scope.expr(e)));
                out.line(write);
            }
            _ => {
                out.line("_ = pb_sz;");
                out.line(write);
            }
        }
        out.close("}");
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, _message: &str) {
        out.line(format!("if (!{}) return pb_w.fail(PbError.Constraint);", self.scope.expr(cond)));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_w.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        out.open("{");
        let uses = uses_selector(arms);
        if uses {
            out.line(format!("const pb_sel: i64 = {};", self.scope.expr(selector)));
        }
        out.open(format!("switch (p.{}) {{", ident(&m.name)));
        for arm in arms {
            let capture = if arm.ty.is_some() { " |pb_v|" } else { "" };
            out.open(format!(".{} =>{} {{", ident(&arm.name), capture));
            if let Some(test) = arm_test(arm, arms, "pb_sel", &ZIG_LOGIC) {
                out.line(format!("if (!{}) return pb_w.fail(PbError.Mismatch);", test));
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("try pb_w.checkLen(pb_v.len, {});", self.scope.expr(e)));
                    }
                    out.line("try pb_w.writeBytes(pb_v);");
                }
                (Some(_), Some(codec), None) => write_elem(out, codec, "pb_v"),
                _ => {}
            }
            out.close("},");
        }
        out.close("}");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("const pb_win{} = pb_w.positionBits();", id));
            out.line(format!("const pb_wsz{}: i64 = {};", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("try pb_w.endWindow(pb_win{}, pb_wsz{}, {});", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("const {} = pb_w.positionBits();", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("const pbc_{}: i64 = {};", m.name, self.scope.expr(value)));
        } else {
            out.line(format!(
                "const pbc_{}: {} = {};",
                m.name,
                scalar_type(&m.ty),
                store_value(self.scope.expr(value), &m.ty)
            ));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            let f = if *signed { "checkI" } else { "checkU" };
            out.line(format!("try pb_w.{}({}, {});", f, v, width));
        }
        let bits = format!("@as(u64, @bitCast({}))", v);
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("try pb_w.writeUint({}, {}, {});", bits, nbytes, Zig::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("pb_w.patchUint({}, {}, {}, {});", mark_var(at), bits, nbytes, Zig::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("try pb_w.writeBits({}, {});", bits, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pb_w.patchBits({}, {}, {});", mark_var(at), bits, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("try pb_w.writeVarint({}, {});", k.id(), bits)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("try pb_w.writeZeroBits(@intCast(pbPad(pb_w.positionBits() - pb_start, {})));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let s = format!("p.{}", ident(&m.name));
        out.line(format!("try pb_w.checkText({}, {});", s, !matches!(mode, StrMode::CString)));
        if m.encoding != TextEncoding::Utf8 || matches!(mode, StrMode::Terminated { .. }) {
            self.encoded_string(out, m, mode, array);
            return;
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("try pb_w.writeBytes({});", s));
                out.line("try pb_w.writeBits(0, 8);");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("try pb_w.checkPrefix({}.len, {});", s, width));
                write_elem(out, prefix, &format!("@as(u64, {}.len)", s));
                out.line(format!("try pb_w.writeBytes({});", s));
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.open("{");
                out.line(format!("const pb_n = {};", self.scope.expr(e)));
                out.line(format!("try pb_w.checkFits({}.len, pb_n);", s));
                out.line(format!("try pb_w.writeBytes({});", s));
                out.line(format!("try pb_w.writeZeroBits((pb_n - @as(i64, @intCast({}.len))) * 8);", s));
                out.close("}");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("try pb_w.checkLen({}.len, {});", s, self.scope.expr(e)));
                out.line(format!("try pb_w.writeBytes({});", s));
            }
            _ => out.line(format!("try pb_w.writeBytes({});", s)),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("try pb_w.writeZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("try pb_w.writeZeroBits(@max({}, 0) *% {});", self.scope.expr(e), bits))
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, _ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, &format!("p.{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("try pb_w.checkLen({}.len, {});", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.open("{");
            out.line("const pb_from = pb_w.positionBits();");
            out.line(format!("try pb_w.writeBytes({});", place));
            out.line(format!("try pb_w.checkNoTerm(pb_from, {});", byte_list(term)));
            out.line(format!("try pb_w.writeBytes({});", byte_list(term)));
            out.close("}");
        } else if ty.is_byte() {
            out.line(format!("try pb_w.writeBytes({});", place));
        } else {
            out.open(format!("for ({}, 0..) |pb_v, pb_i| {{", place));
            out.line("pb_w.atIndex(pb_i);");
            write_elem(out, codec, "pb_v");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        if parts.is_empty() {
            out.line("const pb_c: u64 = 0;");
        } else {
            out.line("var pb_c: u64 = 0;");
        }
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!("pb_c |= (pbToBits(p.{}) & 0x{:x}) << {};", ident(&m.name), mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("try pb_w.writeUint(pb_c, {}, {});", nbytes, Zig::little(endian)))
            }
            _ => out.line(format!("try pb_w.writeBits(pb_c, {});", container_width)),
        }
        out.close("}");
    }
}
