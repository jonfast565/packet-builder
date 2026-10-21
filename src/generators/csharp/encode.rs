//! C# encoder statements.

use super::decode::{byte_list, call_args};
use super::expr::store_value;
use super::naming::{CSharp, arm_class, scalar_type};
use crate::generators::common::union::{C_LOGIC, arm_test, mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

fn write_elem(scope: &Scope<'_, CSharp>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    match ty {
        ValueType::Int { width, signed } if ty.needs_range_check() => {
            if *signed {
                out.line(format!("pbW.CheckI((long){}, {});", v, width));
            } else {
                out.line(format!("pbW.CheckU((ulong){}, {});", v, width));
            }
        }
        ValueType::Mac => out.line(format!("pbW.CheckLen({}.Length, 6);", v)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.WriteUint(unchecked((ulong){}), {}, {});", v, nbytes, CSharp::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.WriteBits(unchecked((ulong){}), {});", v, width)),
        Codec::Float { width: 32, endian } => out.line(format!(
            "pbW.WriteUint(unchecked((uint)BitConverter.SingleToInt32Bits({})), 4, {});",
            v,
            CSharp::little(endian)
        )),
        Codec::Float { endian, .. } => out.line(format!(
            "pbW.WriteUint(unchecked((ulong)BitConverter.DoubleToInt64Bits({})), 8, {});",
            v,
            CSharp::little(endian)
        )),
        Codec::Mac => out.line(format!("pbW.WriteBytes({});", v)),
        Codec::Varint(k) => out.line(format!("pbW.WriteVarint({}, unchecked((ulong){}));", k.id(), v)),
        Codec::Packet(r) => out.line(format!("{}.EncodeTo(pbW{});", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, CSharp>,
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
        out.line(format!(
            "if (!{}) throw pbW.Error(PbErrorKind.Constraint, {});",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbW.At(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        out.open("{");
        if uses_selector(arms) {
            out.line(format!("long pbSel = {};", self.scope.expr(selector)));
        }
        out.line(format!("switch ({})", self.scope.field(m)));
        out.open("{");
        for arm in arms {
            let class = format!("{}.{}", u, arm_class(u, arm));
            let bind = if arm.ty.is_some() { "pbV" } else { "_" };
            out.open(format!("case {} {}:", class, bind));
            if let Some(test) = arm_test(arm, arms, "pbSel", &C_LOGIC) {
                out.line(format!(
                    "if (!{}) throw pbW.Error(PbErrorKind.Mismatch, {});",
                    test,
                    string_literal(&mismatch_message(&m.name, arm))
                ));
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pbW.CheckLen(pbV.Value.Length, {});", self.scope.expr(e)));
                    }
                    out.line("pbW.WriteBytes(pbV.Value);");
                }
                (Some(ty), Some(codec), None) => write_elem(&self.scope, out, codec, ty, "pbV.Value"),
                _ => {}
            }
            out.line("break;");
            out.pop();
        }
        out.open("default:");
        out.line(format!(
            "throw pbW.Error(PbErrorKind.Invalid, {});",
            string_literal(&format!("`{}` holds no known arm", m.name))
        ));
        out.pop();
        out.close("}");
        out.close("}");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("var pbS = pbW.Sub({}, {}, {});", from, self.scope.expr(offset), CSharp::flag(root)));
        out.line(format!("{}.EncodeTo(pbS{});", self.scope.field(m), call_args(&self.scope, target)));
        out.line("pbW.Place(pbS);");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("long pb_win{} = pbW.PositionBits;", id));
            out.line(format!("long pb_wsz{} = {};", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pbW.EndWindow(pb_win{}, pb_wsz{}, {});", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("long {} = pbW.PositionBits;", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pbW.PositionBits;", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("long pbc_{} = {};", m.name, self.scope.expr(value)));
        } else {
            out.line(format!(
                "{} pbc_{} = {};",
                scalar_type(&m.ty),
                m.name,
                store_value(self.scope.expr(value), &m.ty)
            ));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("pbW.CheckI({}, {});", v, width));
            } else {
                out.line(format!("pbW.CheckU(unchecked((ulong){}), {});", v, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pbW.WriteUint(unchecked((ulong){}), {}, {});", v, nbytes, CSharp::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => out.line(format!(
                "pbW.PatchUint({}, unchecked((ulong){}), {}, {});",
                mark_var(at),
                v,
                nbytes,
                CSharp::little(endian)
            )),
            (Codec::Bits { width }, None) => out.line(format!("pbW.WriteBits(unchecked((ulong){}), {});", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pbW.PatchBits({}, unchecked((ulong){}), {});", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("pbW.WriteVarint({}, unchecked((ulong){}));", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbW.WriteZeroBits(Pb.Pad(pbW.PositionBits - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("var pbB = pbW.Utf8Bytes({});", self.scope.field(m)));
        } else {
            out.line(format!("var pbB = pbW.TextBytes({}, {});", self.scope.field(m), m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pbW.CheckNoNul(pbB);");
                out.line("pbW.WriteBytes(pbB);");
                out.line("pbW.WriteBytes(new byte[1]);");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("pbW.CheckNoTerm(pbB, {});", byte_list(term)));
                out.line("pbW.WriteBytes(pbB);");
                out.line(format!("pbW.WriteBytes({});", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pbW.CheckU((ulong)pbB.Length, {});", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "pbB.Length");
                out.line("pbW.WriteBytes(pbB);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("long pbN = {};", self.scope.expr(e)));
                out.line("pbW.CheckFits(pbB.Length, pbN);");
                out.line("pbW.WriteBytes(pbB);");
                out.line("pbW.WriteZeroBits((pbN - pbB.Length) * 8);");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pbW.CheckLen(pbB.Length, {});", self.scope.expr(e)));
                out.line("pbW.WriteBytes(pbB);");
            }
            _ => out.line("pbW.WriteBytes(pbB);"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.WriteZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbW.WriteZeroBits(Math.Max({}, 0L) * {});", self.scope.expr(e), bits))
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
        out.line(format!("pbW.AdoptVersion((long){}, {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &self.scope.field(m));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.scope.field(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pbW.CheckLen({}.Length, {});", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("pbW.CheckNoTerm({}, {});", place, byte_list(term)));
            out.line(format!("pbW.WriteBytes({});", place));
            out.line(format!("pbW.WriteBytes({});", byte_list(term)));
        } else if ty.is_byte() {
            out.line(format!("pbW.WriteBytes({});", place));
        } else {
            out.line(format!("for (int pbI = 0; pbI < {}.Length; pbI++)", place));
            out.open("{");
            out.line("pbW.AtIndex(pbI);");
            out.line(format!("var pbV = {}[pbI];", place));
            write_elem(&self.scope, out, codec, ty, "pbV");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("ulong pbC = 0;");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = self.scope.field(m);
            if part.signed {
                out.line(format!("pbW.CheckI((long){}, {});", place, part.width));
            } else {
                out.line(format!("pbW.CheckU((ulong){}, {});", place, part.width));
            }
            out.line(format!("pbC |= (unchecked((ulong){}) & 0x{:x}UL) << {};", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.WriteUint(pbC, {}, {});", nbytes, CSharp::little(endian)))
            }
            _ => out.line(format!("pbW.WriteBits(pbC, {});", container_width)),
        }
        out.close("}");
    }
}
