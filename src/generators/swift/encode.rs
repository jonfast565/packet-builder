//! Swift encoder statements.

use super::decode::{byte_list, call_args};
use super::expr::{negate, store_value};
use super::naming::{Swift, case_name, ident, scalar_type};
use crate::generators::common::union::{C_LOGIC, arm_test, mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, ValueType};

/// Statements that write one element held in `v`.
fn write_elem(scope: &Scope<'_, Swift>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("try pbW.checkI(Int64(truncatingIfNeeded: {}), {})", v, width));
        } else {
            out.line(format!("try pbW.checkU(UInt64(truncatingIfNeeded: {}), {})", v, width));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.writeUInt(UInt64(truncatingIfNeeded: {}), {}, {})", v, nbytes, Swift::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.writeBits(UInt64(truncatingIfNeeded: {}), {})", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pbW.writeUInt(UInt64({}.bitPattern), 4, {})", v, Swift::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pbW.writeUInt({}.bitPattern, 8, {})", v, Swift::little(endian)))
        }
        Codec::Mac => out.line(format!("try pbW.writeMac({})", v)),
        Codec::Varint(k) => out.line(format!("try pbW.writeVarint({}, UInt64(truncatingIfNeeded: {}))", k.id(), v)),
        Codec::Packet(r) => out.line(format!("try {}.encodeTo(pbW{})", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Swift>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }

    fn fail(&self, kind: &str, message: &str) -> String {
        format!("throw pbW.error(.{}, {})", kind, string_literal(message))
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!("if {} {{ {} }}", negate(self.scope.expr(cond)), self.fail("constraint", message)));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbW.at({})", string_literal(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        if !matches!(m.ty, ValueType::Union(_)) {
            return;
        }
        out.open("do {");
        if uses_selector(arms) {
            out.line(format!("let pb_sel: Int64 = {}", self.scope.expr(selector)));
        }
        out.line(format!("switch p.{} {{", ident(&m.name)));
        for arm in arms {
            let v = case_name(arm);
            let pat = if arm.ty.is_some() { format!("case .{}(let pb_v):", v) } else { format!("case .{}:", v) };
            out.line(pat);
            out.push();
            let mut wrote = false;
            if let Some(test) = arm_test(arm, arms, "pb_sel", &C_LOGIC) {
                out.line(format!(
                    "if {} {{ {} }}",
                    negate(test),
                    self.fail("mismatch", &mismatch_message(&m.name, arm))
                ));
                wrote = true;
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("try pbW.checkLen(pb_v.count, {})", self.scope.expr(e)));
                    }
                    out.line("pbW.writeBytes(pb_v)");
                    wrote = true;
                }
                (Some(ty), Some(codec), None) => {
                    write_elem(&self.scope, out, codec, ty, "pb_v");
                    wrote = true;
                }
                (Some(_), ..) => {
                    out.line("_ = pb_v");
                    wrote = true;
                }
                _ => {}
            }
            if !wrote {
                out.line("break");
            }
            out.pop();
        }
        out.line("}");
        out.close("}");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("do {");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("let pb_s = try pbW.sub({}, {}, {})", from, self.scope.expr(offset), root));
        out.line(format!("try p.{}.encodeTo(pb_s{})", ident(&m.name), call_args(&self.scope, target)));
        out.line("pbW.place(pb_s)");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("let pb_win{} = pbW.positionBits()", id));
            out.line(format!("let pb_wsz{}: Int64 = {}", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("try pbW.endWindow(pb_win{}, pb_wsz{}, {})", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("let {} = pbW.positionBits()", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pbW.positionBits()", mark_var(mark)));
    }

    fn declare_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("var {} = pbW.positionBits()", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("let pbc_{}: Int64 = {}", m.name, self.scope.expr(value)));
        } else {
            out.line(format!(
                "let pbc_{}: {} = {}",
                m.name,
                scalar_type(&m.ty),
                store_value(self.scope.expr(value), &m.ty)
            ));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("try pbW.checkI({}, {})", v, width));
            } else {
                out.line(format!("try pbW.checkU(UInt64(truncatingIfNeeded: {}), {})", v, width));
            }
        }
        let u = format!("UInt64(truncatingIfNeeded: {})", v);
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pbW.writeUInt({}, {}, {})", u, nbytes, Swift::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("pbW.patchUInt({}, {}, {}, {})", mark_var(at), u, nbytes, Swift::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("pbW.writeBits({}, {})", u, width)),
            (Codec::Bits { width }, Some(at)) => out.line(format!("pbW.patchBits({}, {}, {})", mark_var(at), u, width)),
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("try pbW.writeVarint({}, {})", k.id(), u)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbW.writeZeroBits(pbPad(pbW.positionBits() - pb_start, {}))", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("do {");
        out.line(format!("let pb_b = try pbW.text(p.{}, {})", ident(&m.name), m.encoding.id()));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("try pbW.checkNoNul(pb_b)");
                out.line("pbW.writeBytes(pb_b)");
                out.line("pbW.writeBytes([0])");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("try pbW.checkNoTerm(pb_b, {})", byte_list(term)));
                out.line("pbW.writeBytes(pb_b)");
                out.line(format!("pbW.writeBytes({} as [UInt8])", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("try pbW.checkU(UInt64(pb_b.count), {})", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "pb_b.count");
                out.line("pbW.writeBytes(pb_b)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("let pb_n: Int64 = {}", self.scope.expr(e)));
                out.line("try pbW.checkFits(pb_b.count, pb_n)");
                out.line("pbW.writeBytes(pb_b)");
                out.line("pbW.writeZeroBits((Int(pb_n) - pb_b.count) * 8)");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("try pbW.checkLen(pb_b.count, {})", self.scope.expr(e)));
                out.line("pbW.writeBytes(pb_b)");
            }
            _ => out.line("pbW.writeBytes(pb_b)"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.writeZeroBits({})", bits)),
            Some(Count::Expr(e)) => out.line(format!("try pbW.writeZeroCount({}, {})", self.scope.expr(e), bits)),
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &format!("p.{}", ident(&m.name)));
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if {} {{", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("}");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("try pbW.adoptVersion(pbI(p.{}), {}, {})", ident(&m.name), min, latest));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("try pbW.checkLen({}.count, {})", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("try pbW.checkNoTerm({}, {})", place, byte_list(term)));
            out.line(format!("pbW.writeBytes({})", place));
            out.line(format!("pbW.writeBytes({} as [UInt8])", byte_list(term)));
            return;
        }
        if ty.is_byte() {
            out.line(format!("pbW.writeBytes({})", place));
        } else {
            out.open(format!("for (pb_i, pb_v) in {}.enumerated() {{", place));
            out.line("pbW.atIndex(pb_i)");
            write_elem(&self.scope, out, codec, ty, "pb_v");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("do {");
        out.line("var pb_c: UInt64 = 0");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", ident(&m.name));
            if part.signed {
                out.line(format!("try pbW.checkI(Int64(truncatingIfNeeded: {}), {})", place, part.width));
            } else {
                out.line(format!("try pbW.checkU(UInt64(truncatingIfNeeded: {}), {})", place, part.width));
            }
            out.line(format!(
                "pb_c |= (UInt64(truncatingIfNeeded: {}) & 0x{:x}) << {}",
                place,
                mask(part.width),
                part.shift
            ));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.writeUInt(pb_c, {}, {})", nbytes, Swift::little(endian)))
            }
            _ => out.line(format!("pbW.writeBits(pb_c, {})", container_width)),
        }
        out.close("}");
    }
}
