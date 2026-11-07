//! Object Pascal encoder statements.

use super::decode::{arm_test, call_args};
use super::expr::store_value;
use super::locals::Locals;
use super::naming::{Pascal, arm_class, byte_list, pas_string, scalar_type};
use crate::generators::common::union::{mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

fn write_elem(scope: &Scope<'_, Pascal>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    match ty {
        ValueType::Int { width, signed } if ty.needs_range_check() => {
            if *signed {
                out.line(format!("pbW.CheckI(Int64({}), {});", v, width));
            } else {
                out.line(format!("pbW.CheckU(UInt64({}), {});", v, width));
            }
        }
        ValueType::Mac => out.line(format!("pbW.CheckLen(Length({}), 6);", v)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.WriteUint(UInt64({}), {}, {});", v, nbytes, Pascal::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.WriteBits(UInt64({}), {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pbW.WriteUint(PbSingleToBits({}), 4, {});", v, Pascal::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pbW.WriteUint(PbDoubleToBits({}), 8, {});", v, Pascal::little(endian)))
        }
        Codec::Mac => out.line(format!("pbW.WriteBytes({});", v)),
        Codec::Varint(k) => out.line(format!("pbW.WriteVarint({}, UInt64({}));", k.id(), v)),
        Codec::Packet(r) => out.line(format!("{}.EncodeTo(pbW{});", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Pascal>,
    pub locals: &'a Locals,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet, locals: &'a Locals) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode), locals }
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if not {} then raise pbW.Error(pekConstraint, {});",
            self.scope.expr(cond),
            pas_string(message)
        ));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbW.At({});", pas_string(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = self.scope.field(m);
        if uses_selector(arms) {
            let sel = self.locals.var("pbSel", "Int64");
            out.line(format!("{} := {};", sel, self.scope.expr(selector)));
        }
        for (i, arm) in arms.iter().enumerate() {
            let class = arm_class(u, arm);
            out.line(format!("{}if {} is {} then", if i == 0 { "" } else { "else " }, place, class));
            out.open("begin");
            if let Some(test) = arm_test(arm, arms, "pbSel") {
                out.line(format!(
                    "if not {} then raise pbW.Error(pekMismatch, {});",
                    test,
                    pas_string(&mismatch_message(&m.name, arm))
                ));
            }
            let value = format!("{}({}).Value", class, place);
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pbW.CheckLen(Length({}), {});", value, self.scope.expr(e)));
                    }
                    out.line(format!("pbW.WriteBytes({});", value));
                }
                (Some(ty), Some(codec), None) => write_elem(&self.scope, out, codec, ty, &value),
                _ => {}
            }
            out.close("end");
        }
        out.line("else");
        out.line(format!(
            "  raise pbW.Error(pekInvalid, {});",
            pas_string(&format!("`{}` holds no known arm", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        let s = self.locals.var("pbS", "TPbWriter");
        out.line(format!("{} := pbW.Sub({}, {}, {});", s, from, self.scope.expr(offset), Pascal::flag(root)));
        out.open("try");
        out.line(format!("{}.EncodeTo(pbS{});", self.scope.field(m), call_args(&self.scope, target)));
        out.line("pbW.Place(pbS);");
        out.close("finally");
        out.push();
        out.line("pbS.Free;");
        out.close("end;");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            let w = self.locals.var(format!("pb_win{}", id), "Int64");
            let z = self.locals.var(format!("pb_wsz{}", id), "Int64");
            out.line(format!("{} := pbW.PositionBits;", w));
            out.line(format!("{} := {};", z, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pbW.EndWindow(pb_win{}, pb_wsz{}, {});", id, id, Pascal::flag(exact)));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals.var(mark_var(mark), "Int64");
        out.line(format!("{} := pbW.PositionBits;", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        let name = format!("pbc_{}", m.name);
        if m.is_derived() {
            self.locals.var(&name, "Int64");
            out.line(format!("{} := {};", name, self.scope.expr(value)));
        } else {
            self.locals.var(&name, &scalar_type(&m.ty));
            out.line(format!("{} := {};", name, store_value(self.scope.expr(value), &m.ty)));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("pbW.CheckI({}, {});", v, width));
            } else {
                out.line(format!("pbW.CheckU(UInt64({}), {});", v, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pbW.WriteUint(UInt64({}), {}, {});", v, nbytes, Pascal::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => out.line(format!(
                "pbW.PatchUint({}, UInt64({}), {}, {});",
                mark_var(at),
                v,
                nbytes,
                Pascal::little(endian)
            )),
            (Codec::Bits { width }, None) => out.line(format!("pbW.WriteBits(UInt64({}), {});", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pbW.PatchBits({}, UInt64({}), {});", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("pbW.WriteVarint({}, UInt64({}));", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbW.WriteZeroBits(PbPad(pbW.PositionBits - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        self.locals.var("pbB", "TBytes");
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("pbB := pbW.Utf8Bytes({});", self.scope.field(m)));
        } else {
            out.line(format!("pbB := pbW.TextBytes({}, {});", self.scope.field(m), m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pbW.CheckNoNul(pbB);");
                out.line("pbW.WriteBytes(pbB);");
                out.line("pbW.WriteBytes([0]);");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("pbW.CheckNoTerm(pbB, {});", byte_list(term)));
                out.line("pbW.WriteBytes(pbB);");
                out.line(format!("pbW.WriteBytes({});", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pbW.CheckU(UInt64(Length(pbB)), {});", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "Length(pbB)");
                out.line("pbW.WriteBytes(pbB);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                self.locals.var("pbLen", "Int64");
                out.line(format!("pbLen := {};", self.scope.expr(e)));
                out.line("pbW.CheckFits(Length(pbB), pbLen);");
                out.line("pbW.WriteBytes(pbB);");
                out.line("pbW.WriteZeroBits((pbLen - Length(pbB)) * 8);");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pbW.CheckLen(Length(pbB), {});", self.scope.expr(e)));
                out.line("pbW.WriteBytes(pbB);");
            }
            _ => out.line("pbW.WriteBytes(pbB);"),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.WriteZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbW.WriteZeroBits(PbMaxI({}, 0) * {});", self.scope.expr(e), bits))
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.line(format!("if {} then", self.scope.expr(cond)));
        out.open("begin");
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("end;");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("pbW.AdoptVersion(Int64({}), {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &self.scope.field(m));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.scope.field(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pbW.CheckLen(Length({}), {});", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("pbW.CheckNoTerm({}, {});", place, byte_list(term)));
            out.line(format!("pbW.WriteBytes({});", place));
            out.line(format!("pbW.WriteBytes({});", byte_list(term)));
        } else if ty.is_byte() {
            out.line(format!("pbW.WriteBytes({});", place));
        } else {
            self.locals.var("pbI", "Integer");
            out.line(format!("for pbI := 0 to High({}) do", place));
            out.open("begin");
            out.line("pbW.AtIndex(pbI);");
            write_elem(&self.scope, out, codec, ty, &format!("{}[pbI]", place));
            out.close("end;");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let c = self.locals.var("pbC", "UInt64");
        out.line(format!("{} := 0;", c));
        for part in parts {
            let m = self.scope.member(part.member);
            let place = self.scope.field(m);
            if part.signed {
                out.line(format!("pbW.CheckI(Int64({}), {});", place, part.width));
            } else {
                out.line(format!("pbW.CheckU(UInt64({}), {});", place, part.width));
            }
            out.line(format!(
                "pbC := pbC or ((UInt64({}) and UInt64(${:X})) shl {});",
                place,
                mask(part.width),
                part.shift
            ));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.WriteUint(pbC, {}, {});", nbytes, Pascal::little(endian)))
            }
            _ => out.line(format!("pbW.WriteBits(pbC, {});", container_width)),
        }
    }
}
