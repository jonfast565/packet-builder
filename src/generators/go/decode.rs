//! Go decoder statements. Decoding records the first error in the reader and
//! carries on with zero values, so statements need no error checks.

use super::expr::store_value;
use super::naming::{Go, field_name, member_type, scalar_type};
use super::packet::arm_kind;
use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, TextEncoding, ValueType};

/// `[]byte{0x0d, 0x0a}`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("[]byte{{{}}}", items.join(", "))
}

fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, Go::little(endian)),
        Codec::Bits { width } => format!("pbR.ReadBits({})", width),
        Codec::Float { width: 32, endian } => {
            return format!("math.Float32frombits(uint32(pbR.ReadUint(4, {})))", Go::little(endian));
        }
        Codec::Float { endian, .. } => return format!("math.Float64frombits(pbR.ReadUint(8, {}))", Go::little(endian)),
        Codec::Mac => return "pbR.ReadMac()".into(),
        Codec::Varint(k) => format!("pbR.ReadVarint({})", k.id()),
        Codec::Packet(n) => return format!("pbDecode{}(pbR)", n),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("{}(pbSext({}, {}))", st, raw, width),
        _ => format!("{}({})", st, raw),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Go>,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode) }
    }

    /// Statements that decode `arm` of union `u` into `place`.
    fn arm(&self, out: &mut Out, u: &str, place: &str, arm: &Arm) {
        out.line(format!("{}.Kind = {}", place, arm_kind(u, arm)));
        let target = format!("{}.{}", place, variant_name(arm));
        match (&arm.ty, &arm.codec, &arm.count) {
            (Some(_), _, Some(Count::Expr(e))) => {
                out.line(format!("{} = pbR.ReadBytes(pbR.Count({}, 8))", target, self.scope.expr(e)))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                out.line(format!("{} = pbR.ReadBytes(pbR.RemainingBits() / 8)", target))
            }
            (Some(ValueType::Packet(n)), _, None) => {
                out.line(format!("pbV := pbDecode{}(pbR)", n));
                out.line(format!("{} = &pbV", target));
            }
            (Some(ty), Some(codec), None) => out.line(format!("{} = {}", target, read_elem(codec, ty))),
            (_, _, Some(Count::Until(_) | Count::Terminated { .. })) => {
                unreachable!("union arms have no until or term")
            }
            _ => {}
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.open(format!("if !{} {{", self.scope.expr(cond)));
        out.line(format!("pbR.Fail(PbConstraint, \"%s\", {})", string_literal(message)));
        out.close("}");
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbR.At(\"{}\")", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = format!("p.{}", field_name(&m.name));
        out.line(format!("switch pbSel := {}; pbSel {{", self.scope.expr(selector)));
        for arm in arms.iter().filter(|a| !a.default) {
            let values: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            out.line(format!("case {}:", values.join(", ")));
            out.push();
            self.arm(out, u, &place, arm);
            out.pop();
        }
        out.line("default:");
        out.push();
        match arms.iter().find(|a| a.default) {
            Some(arm) => self.arm(out, u, &place, arm),
            None => out.line(format!("pbR.Fail(PbInvalid, \"no arm of `{}` for %d\", pbSel)", m.name)),
        }
        out.pop();
        out.line("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("pb_win{} := pbR.PushLimit({})", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pbR.PopLimit(pb_win{}, {})", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} := pbR.PositionBits()", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.open(format!("if pbV := {}; int64(p.{}) != pbV {{", self.scope.expr(value), field_name(&m.name)));
        out.line(format!(
            "pbR.Fail(PbMismatch, \"%s\", {})",
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
        out.close("}");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbR.SkipBits(pbPad(pbR.PositionBits()-pb_start, {}))", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {}", field_name(&m.name), store_value(e, self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pbR.ReadCString()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pbR.ReadUntil({}, {})", byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pbR.ReadBytes(pbR.Count(int64({}), 8))", read_elem(prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pbR.ReadBytes(pbR.Count({}, 8))", self.scope.expr(e)),
            _ => "pbR.ReadBytes(pbR.RemainingBits()/8)".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("p.{} = pbR.Text({}, {})", field_name(&m.name), raw, padded));
        } else {
            out.line(format!("p.{} = pbR.TextEnc({}, {}, {})", field_name(&m.name), raw, m.encoding.id(), padded));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbR.SkipBits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbR.SkipBits(pbR.Count({}, {}) * {})", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pbR.SkipBits(pbR.RemainingBits())"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {}", field_name(&m.name), read_elem(codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", field_name(&m.name));
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("pbR.Count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = pbR.ReadBytes({})", target, n));
                } else {
                    out.open("{");
                    out.line(format!("pbN := {}", n));
                    out.line(format!("{} = make({}, 0, pbN)", target, member_type(m)));
                    out.open("for pbI := 0; pbI < pbN && pbR.Err() == nil; pbI++ {");
                    out.line("pbR.AtIndex(pbI)");
                    out.line(format!("{} = append({}, {})", target, target, read_elem(codec, ty)));
                    out.close("}");
                    out.close("}");
                }
            }
            Count::Terminated { term, optional } => {
                out.line(format!("{} = pbR.ReadUntil({}, {})", target, byte_list(term), optional))
            }
            Count::Until(cond) => {
                out.line(format!("{} = {}{{}}", target, member_type(m)));
                out.open("for pbR.Err() == nil && pbR.RemainingBits() > 0 {");
                out.line(format!("pbR.AtIndex(len({}))", target));
                out.line(format!("pbLast := {}", read_elem(codec, ty)));
                out.line(format!("pbStop := {}", self.scope.expr(cond)));
                out.line(format!("{} = append({}, pbLast)", target, target));
                out.open("if pbStop {");
                out.line("break");
                out.close("}");
                out.close("}");
            }
            Count::Remaining => {
                if ty.is_byte() {
                    out.line(format!("{} = pbR.ReadBytes(pbR.RemainingBits() / 8)", target));
                } else {
                    out.line(format!("{} = {}{{}}", target, member_type(m)));
                    out.open("for pbR.Err() == nil && pbR.RemainingBits() > 0 {");
                    out.line(format!("pbR.AtIndex(len({}))", target));
                    out.line(format!("{} = append({}, {})", target, target, read_elem(codec, ty)));
                    out.close("}");
                }
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, Go::little(endian)),
            _ => format!("pbR.ReadBits({})", container_width),
        };
        out.line(format!("pbC := {}", raw));
        out.line("_ = pbC");
        for part in parts {
            let m = self.scope.member(part.member);
            let st = scalar_type(&m.ty);
            let bits = format!("((pbC >> {}) & 0x{:x})", part.shift, mask(part.width));
            let v = if part.signed {
                format!("{}(pbSext({}, {}))", st, bits, part.width)
            } else {
                format!("{}({})", st, bits)
            };
            out.line(format!("p.{} = {}", field_name(&m.name), v));
        }
        out.close("}");
    }
}
