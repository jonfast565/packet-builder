//! Go encoder statements. Like decoding, the writer records the first error.

use super::expr::store_value;
use super::naming::{Go, field_name};
use super::packet::arm_kind;
use crate::generators::common::union::{C_LOGIC, arm_test, mismatch_message, uses_selector, variant_name};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("pbW.CheckI(int64({}), {})", v, width));
        } else {
            out.line(format!("pbW.CheckU(uint64({}), {})", v, width));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.WriteUint(uint64({}), {}, {})", v, nbytes, Go::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.WriteBits(uint64({}), {})", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pbW.WriteUint(uint64(math.Float32bits({})), 4, {})", v, Go::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pbW.WriteUint(math.Float64bits({}), 8, {})", v, Go::little(endian)))
        }
        Codec::Mac => out.line(format!("pbW.WriteBytes({}[:])", v)),
        Codec::Packet(_) => out.line(format!("{}.EncodeTo(pbW)", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Go>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.open(format!("if !{} {{", self.scope.expr(cond)));
        out.line(format!("pbW.Fail(PbConstraint, \"%s\", {})", string_literal(message)));
        out.close("}");
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbW.At(\"{}\")", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = format!("p.{}", field_name(&m.name));
        out.open("{");
        if uses_selector(arms) {
            out.line(format!("pbSel := {}", self.scope.expr(selector)));
        }
        out.line(format!("switch {}.Kind {{", place));
        for arm in arms {
            out.line(format!("case {}:", arm_kind(u, arm)));
            out.push();
            if let Some(test) = arm_test(arm, arms, "pbSel", &C_LOGIC) {
                out.open(format!("if !{} {{", test));
                out.line(format!("pbW.Fail(PbMismatch, \"%s\", {})", string_literal(&mismatch_message(&m.name, arm))));
                out.close("}");
            }
            let target = format!("{}.{}", place, variant_name(arm));
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pbW.CheckLen(len({}), {})", target, self.scope.expr(e)));
                    }
                    out.line(format!("pbW.WriteBytes({})", target));
                }
                (Some(ValueType::Packet(n)), _, None) => {
                    out.line(format!("pbV := {}", target));
                    out.open("if pbV == nil {");
                    out.line(format!("pbV = &{}{{}}", n));
                    out.close("}");
                    out.line("pbV.EncodeTo(pbW)");
                }
                (Some(ty), Some(codec), None) => write_elem(out, codec, ty, &target),
                _ => {}
            }
            out.pop();
        }
        out.line("default:");
        out.line(format!(
            "\tpbW.Fail(PbInvalid, \"%s\", {})",
            string_literal(&format!("`{}` holds no known arm", m.name))
        ));
        out.line("}");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("pb_win{} := pbW.PositionBits()", id));
            out.line(format!("pb_wsz{} := {}", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pbW.EndWindow(pb_win{}, pb_wsz{}, {})", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} := pbW.PositionBits()", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("var pbc_{} int64 = {}", m.name, self.scope.expr(value)));
        } else {
            out.line(format!("pbc_{} := {}", m.name, store_value(value, self.scope.expr(value), &m.ty)));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("pbW.CheckI({}, {})", v, width));
            } else {
                out.line(format!("pbW.CheckU(uint64({}), {})", v, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pbW.WriteUint(uint64({}), {}, {})", v, nbytes, Go::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("pbW.PatchUint({}, uint64({}), {}, {})", mark_var(at), v, nbytes, Go::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("pbW.WriteBits(uint64({}), {})", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pbW.PatchBits({}, uint64({}), {})", mark_var(at), v, width))
            }
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbW.WriteZeroBits(int64(pbPad(pbW.PositionBits()-pb_start, {})))", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        out.line(format!("pbW.CheckUTF8(p.{})", field_name(&m.name)));
        out.line(format!("pbB := []byte(p.{})", field_name(&m.name)));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pbW.CheckNoNul(pbB)");
                out.line("pbW.WriteBytes(pbB)");
                out.line("pbW.WriteBytes([]byte{0})");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pbW.CheckU(uint64(len(pbB)), {})", width));
                write_elem(out, prefix, &PREFIX_LEN, "len(pbB)");
                out.line("pbW.WriteBytes(pbB)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("pbN := {}", self.scope.expr(e)));
                out.line("pbW.CheckFits(len(pbB), pbN)");
                out.line("pbW.WriteBytes(pbB)");
                out.line("pbW.WriteZeroBits((pbN - int64(len(pbB))) * 8)");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pbW.CheckLen(len(pbB), {})", self.scope.expr(e)));
                out.line("pbW.WriteBytes(pbB)");
            }
            _ => out.line("pbW.WriteBytes(pbB)"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.WriteZeroBits({})", bits)),
            Some(Count::Expr(e)) => out.line(format!("pbW.WriteZeroBits(pbMax({}, 0) * {})", self.scope.expr(e), bits)),
            Some(Count::Remaining) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &format!("p.{}", field_name(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", field_name(&m.name));
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pbW.CheckLen(len({}), {})", place, self.scope.expr(e)));
        }
        if ty.is_byte() {
            out.line(format!("pbW.WriteBytes({})", place));
        } else {
            out.open(format!("for pbI := range {} {{", place));
            out.line("pbW.AtIndex(pbI)");
            write_elem(out, codec, ty, &format!("{}[pbI]", place));
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("var pbC uint64");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", field_name(&m.name));
            if part.signed {
                out.line(format!("pbW.CheckI(int64({}), {})", place, part.width));
            } else {
                out.line(format!("pbW.CheckU(uint64({}), {})", place, part.width));
            }
            out.line(format!("pbC |= (uint64({}) & 0x{:x}) << {}", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.WriteUint(pbC, {}, {})", nbytes, Go::little(endian)))
            }
            _ => out.line(format!("pbW.WriteBits(pbC, {})", container_width)),
        }
        out.close("}");
    }
}
