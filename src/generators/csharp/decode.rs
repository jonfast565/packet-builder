//! C# decoder statements.

use super::expr::store_value;
use super::naming::{CSharp, scalar_type};
use crate::generators::common::union::{C_LOGIC, arm_test, variant_name};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, ValueType};

fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, CSharp::little(endian)),
        Codec::Bits { width } => format!("pbR.ReadBits({})", width),
        Codec::Float { width: 32, endian } => {
            return format!(
                "BitConverter.Int32BitsToSingle(unchecked((int)pbR.ReadUint(4, {})))",
                CSharp::little(endian)
            );
        }
        Codec::Float { endian, .. } => {
            return format!(
                "BitConverter.Int64BitsToDouble(unchecked((long)pbR.ReadUint(8, {})))",
                CSharp::little(endian)
            );
        }
        Codec::Mac => return "pbR.ReadBytes(6)".into(),
        Codec::Packet(n) => return format!("{}.DecodeFrom(pbR)", n),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("unchecked(({})Pb.Sext({}, {}))", st, raw, width),
        _ => format!("unchecked(({}){})", st, raw),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, CSharp>,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode) }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let class = format!("{}.{}", u, variant_name(arm));
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => format!("new {}()", class),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("new {} {{ Value = pbR.ReadBytes(pbR.Count({}, 8)) }}", class, self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("new {} {{ Value = pbR.ReadBytes(pbR.RemainingBits / 8) }}", class)
            }
            (Some(ty), Some(codec), None) => format!("new {} {{ Value = {} }}", class, read_elem(codec, ty)),
            _ => format!("new {}()", class),
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if (!{}) throw pbR.Error(PbErrorKind.Constraint, {});",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbR.At(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = self.scope.field(m);
        out.open("{");
        out.line(format!("long pbSel = {};", self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "pbSel", &C_LOGIC).unwrap_or_else(|| "true".into());
            out.line(format!(
                "{}if {} {} = {};",
                if first { "" } else { "else " },
                test,
                place,
                self.arm_value(u, arm)
            ));
            first = false;
        }
        let otherwise = match arms.iter().find(|a| a.default) {
            Some(arm) => format!("{} = {};", place, self.arm_value(u, arm)),
            None => format!("throw pbR.Error(PbErrorKind.Invalid, $\"no arm of `{}` for {{pbSel}}\");", m.name),
        };
        out.line(if first { otherwise } else { format!("else {}", otherwise) });
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("long pb_win{} = pbR.PushLimit({});", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pbR.PopLimit(pb_win{}, {});", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("long {} = pbR.PositionBits;", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if (unchecked((long){}) != {}) throw pbR.Error(PbErrorKind.Mismatch, {});",
            self.scope.field(m),
            self.scope.expr(value),
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbR.SkipBits(Pb.Pad(pbR.PositionBits - pb_start, {}));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} = {};", self.scope.field(m), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pbR.ReadCString()".to_string(),
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pbR.ReadBytes(pbR.Count(unchecked((long){}), 8))", read_elem(prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pbR.ReadBytes(pbR.Count({}, 8))", self.scope.expr(e)),
            _ => "pbR.ReadBytes(pbR.RemainingBits / 8)".to_string(),
        };
        out.line(format!("{} = pbR.Utf8({}, {});", self.scope.field(m), raw, *mode == StrMode::Padded));
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbR.SkipBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbR.SkipBits((long)pbR.Count({}, {}) * {});", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pbR.SkipBits(pbR.RemainingBits);"),
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("{} = {};", self.scope.field(m), read_elem(codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = self.scope.field(m);
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("pbR.Count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = pbR.ReadBytes({});", target, n));
                } else {
                    out.open("{");
                    out.line(format!("int pbN = {};", n));
                    out.line(format!("var pbA = new {}[pbN];", scalar_type(ty)));
                    out.line("for (int pbI = 0; pbI < pbN; pbI++)");
                    out.open("{");
                    out.line("pbR.AtIndex(pbI);");
                    out.line(format!("pbA[pbI] = {};", read_elem(codec, ty)));
                    out.close("}");
                    out.line(format!("{} = pbA;", target));
                    out.close("}");
                }
            }
            Count::Remaining => {
                if ty.is_byte() {
                    out.line(format!("{} = pbR.ReadBytes(pbR.RemainingBits / 8);", target));
                } else {
                    out.open("{");
                    out.line(format!("var pbL = new List<{}>();", scalar_type(ty)));
                    out.line("while (pbR.RemainingBits > 0)");
                    out.open("{");
                    out.line("pbR.AtIndex(pbL.Count);");
                    out.line(format!("pbL.Add({});", read_elem(codec, ty)));
                    out.close("}");
                    out.line(format!("{} = pbL.ToArray();", target));
                    out.close("}");
                }
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, CSharp::little(endian)),
            _ => format!("pbR.ReadBits({})", container_width),
        };
        out.line(format!("ulong pbC = {};", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let st = scalar_type(&m.ty);
            let bits = format!("((pbC >> {}) & 0x{:x}UL)", part.shift, mask(part.width));
            let v = if part.signed {
                format!("unchecked(({})Pb.Sext({}, {}))", st, bits, part.width)
            } else {
                format!("unchecked(({}){})", st, bits)
            };
            out.line(format!("{} = {};", self.scope.field(m), v));
        }
        out.close("}");
    }
}
