//! Java encoder statements.

use super::decode::{arm_test, byte_list, call_args};
use super::expr::store_value;
use super::naming::{Java, arm_class, class_name, needs_check, scalar_type};
use crate::generators::common::union::{mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// `pbW.checkU(...)`: the range check of a value of type `ty`, if it needs one.
fn range_check(out: &mut Out, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && needs_check(ty)
    {
        let f = if *signed { "checkI" } else { "checkU" };
        out.line(format!("pbW.{}((long){}, {});", f, v, width));
    }
}

fn write_elem(scope: &Scope<'_, Java>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    range_check(out, ty, v);
    if *ty == ValueType::Mac {
        out.line(format!("pbW.checkLen({}.length, 6);", v));
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.writeUint((long){}, {}, {});", v, nbytes, Java::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.writeBits((long){}, {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pbW.writeUint(Float.floatToRawIntBits({}), 4, {});", v, Java::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pbW.writeUint(Double.doubleToRawLongBits({}), 8, {});", v, Java::little(endian)))
        }
        Codec::Mac => out.line(format!("pbW.writeBytes({});", v)),
        Codec::Varint(k) => out.line(format!("pbW.writeVarint({}, (long){});", k.id(), v)),
        Codec::Packet(r) => out.line(format!("{}.encodeTo(pbW{});", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

/// The element count of array member `m` held in `place`.
fn length(m: &Member, place: &str) -> String {
    if m.ty.is_byte() { format!("Pb.len({})", place) } else { format!("{}.length", place) }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Java>,
    /// The generated file's class (union arm classes may be escaped with it).
    outer: &'a str,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet, outer: &'a str) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode), outer }
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if (!{}) throw pbW.error(PbErrorKind.CONSTRAINT, {});",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbW.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let uc = class_name(u);
        out.open("{");
        if uses_selector(arms) {
            out.line(format!("long pbSel = {};", self.scope.expr(selector)));
        }
        out.line(format!("{} pbU = {};", uc, self.scope.field(m)));
        for (i, arm) in arms.iter().enumerate() {
            let class = format!("{}.{}", uc, arm_class(u, arm, self.outer));
            let bind = if arm.ty.is_some() { " pbV" } else { "" };
            let pre = if i == 0 { "" } else { "} else " };
            out.line(format!("{}if (pbU instanceof {}{}) {{", pre, class, bind));
            out.push();
            if let Some(test) = arm_test(arm, arms, "pbSel") {
                out.line(format!(
                    "if (!{}) throw pbW.error(PbErrorKind.MISMATCH, {});",
                    test,
                    string_literal(&mismatch_message(&m.name, arm))
                ));
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pbW.checkLen(Pb.len(pbV.value), {});", self.scope.expr(e)));
                    }
                    out.line("pbW.writeBytes(pbV.value);");
                }
                (Some(ty), Some(codec), None) => write_elem(&self.scope, out, codec, ty, "pbV.value"),
                _ => {}
            }
            out.pop();
        }
        out.open("} else {");
        out.line(format!(
            "throw pbW.error(PbErrorKind.INVALID, {});",
            string_literal(&format!("`{}` holds no known arm", m.name))
        ));
        out.close("}");
        out.close("}");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("PbWriter pbS = pbW.sub({}, {}, {});", from, self.scope.expr(offset), Java::flag(root)));
        out.line(format!("{}.encodeTo(pbS{});", self.scope.field(m), call_args(&self.scope, target)));
        out.line("pbW.place(pbS);");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("long pb_win{} = pbW.positionBits();", id));
            out.line(format!("long pb_wsz{} = {};", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pbW.endWindow(pb_win{}, pb_wsz{}, {});", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("long {} = pbW.positionBits();", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pbW.positionBits();", mark_var(mark)));
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
            let f = if *signed { "checkI" } else { "checkU" };
            out.line(format!("pbW.{}({}, {});", f, v, width));
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pbW.writeUint({}, {}, {});", v, nbytes, Java::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("pbW.patchUint({}, {}, {}, {});", mark_var(at), v, nbytes, Java::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("pbW.writeBits({}, {});", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pbW.patchBits({}, {}, {});", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("pbW.writeVarint({}, {});", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbW.writeZeroBits(Pb.pad(pbW.positionBits() - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("byte[] pbB = pbW.utf8Bytes({});", self.scope.field(m)));
        } else {
            out.line(format!("byte[] pbB = pbW.textBytes({}, {});", self.scope.field(m), m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pbW.checkNoNul(pbB);");
                out.line("pbW.writeBytes(pbB);");
                out.line("pbW.writeBytes(new byte[1]);");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("pbW.checkNoTerm(pbB, {});", byte_list(term)));
                out.line("pbW.writeBytes(pbB);");
                out.line(format!("pbW.writeBytes({});", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pbW.checkU(pbB.length, {});", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "pbB.length");
                out.line("pbW.writeBytes(pbB);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("long pbN = {};", self.scope.expr(e)));
                out.line("pbW.checkFits(pbB.length, pbN);");
                out.line("pbW.writeBytes(pbB);");
                out.line("pbW.writeZeroBits((pbN - pbB.length) * 8);");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pbW.checkLen(pbB.length, {});", self.scope.expr(e)));
                out.line("pbW.writeBytes(pbB);");
            }
            _ => out.line("pbW.writeBytes(pbB);"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.writeZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbW.writeZeroBits(Math.max({}, 0L) * {});", self.scope.expr(e), bits))
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
        out.line(format!("pbW.adoptVersion((long){}, {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &self.scope.field(m));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.scope.field(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pbW.checkLen({}, {});", length(m, &place), self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("pbW.checkNoTerm({}, {});", place, byte_list(term)));
            out.line(format!("pbW.writeBytes({});", place));
            out.line(format!("pbW.writeBytes({});", byte_list(term)));
        } else if m.ty.is_byte() && ty.is_byte() {
            out.line(format!("pbW.writeBytes({});", place));
        } else if m.ty.is_byte() {
            // Bytes written as narrower elements.
            out.line(format!("byte[] pbE = Pb.bytes({});", place));
            out.open("for (int pbI = 0; pbI < pbE.length; pbI++) {");
            out.line("pbW.atIndex(pbI);");
            out.line("int pbV = pbE[pbI] & 0xff;");
            write_elem(&self.scope, out, codec, ty, "pbV");
            out.close("}");
        } else {
            out.open(format!("for (int pbI = 0; pbI < {}.length; pbI++) {{", place));
            out.line("pbW.atIndex(pbI);");
            out.line(format!("var pbV = {}[pbI];", place));
            write_elem(&self.scope, out, codec, ty, "pbV");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("long pbC = 0;");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = self.scope.field(m);
            let f = if part.signed { "checkI" } else { "checkU" };
            out.line(format!("pbW.{}((long){}, {});", f, place, part.width));
            out.line(format!("pbC |= ((long){} & 0x{:x}L) << {};", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.writeUint(pbC, {}, {});", nbytes, Java::little(endian)))
            }
            _ => out.line(format!("pbW.writeBits(pbC, {});", container_width)),
        }
        out.close("}");
    }
}
