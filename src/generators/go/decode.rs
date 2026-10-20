//! Go decoder statements. Decoding records the first error in the reader and
//! carries on with zero values, so statements need no error checks.

use super::expr::store_value;
use super::naming::{Go, field_name, member_type, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask, string_literal};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, TExpr, ValueType};

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

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbR.SkipBits(pbPad(pbR.PositionBits()-pbStart, {}))", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {}", field_name(&m.name), store_value(e, self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pbR.ReadCString()".to_string(),
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pbR.ReadBytes(pbR.Count(int64({}), 8))", read_elem(prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pbR.ReadBytes(pbR.Count({}, 8))", self.scope.expr(e)),
            _ => "pbR.ReadBytes(pbR.RemainingBits()/8)".to_string(),
        };
        out.line(format!("p.{} = pbR.Text({}, {})", field_name(&m.name), raw, *mode == StrMode::Padded));
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbR.SkipBits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbR.SkipBits(pbR.Count({}, {}) * {})", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pbR.SkipBits(pbR.RemainingBits())"),
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
