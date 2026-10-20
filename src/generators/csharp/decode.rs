//! C# decoder statements.

use super::expr::store_value;
use super::naming::{CSharp, arm_class, scalar_type};
use crate::generators::common::union::{C_LOGIC, arm_test};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, CSharp>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// `new byte[] { 0x0d, 0x0a }`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("new byte[] {{ {} }}", items.join(", "))
}

fn read_elem(scope: &Scope<'_, CSharp>, codec: &Codec, ty: &ValueType) -> String {
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
        Codec::Varint(k) => format!("pbR.ReadVarint({})", k.id()),
        Codec::Packet(r) => return format!("{}.DecodeFrom(pbR{})", r.name, call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("unchecked(({})Pb.Sext({}, {}))", st, raw, width),
        _ => format!("unchecked(({}){})", st, raw),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, CSharp>,
    /// Byte buffers are views of the input.
    zero_copy: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, zero_copy: bool) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), zero_copy }
    }

    /// The reader method for a byte buffer: a copy, or a view of the input.
    fn read_bytes(&self) -> &'static str {
        if self.zero_copy { "ReadMemory" } else { "ReadBytes" }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let class = format!("{}.{}", u, arm_class(u, arm));
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => format!("new {}()", class),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("new {} {{ Value = pbR.{}(pbR.Count({}, 8)) }}", class, self.read_bytes(), self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("new {} {{ Value = pbR.{}(pbR.RemainingBits / 8) }}", class, self.read_bytes())
            }
            (Some(ty), Some(codec), None) => {
                format!("new {} {{ Value = {} }}", class, read_elem(&self.scope, codec, ty))
            }
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

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("var pbJ = pbR.Jump({}, {});", from, self.scope.expr(offset)));
        out.line(format!(
            "{} = {}.DecodeFrom(pbR{});",
            self.scope.field(m),
            target.name,
            call_args(&self.scope, target)
        ));
        out.line("pbR.JumpBack(pbJ);");
        out.close("}");
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
            (StrMode::Terminated { term, optional }, _) => {
                format!("pbR.ReadUntil({}, {})", byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pbR.ReadBytes(pbR.Count(unchecked((long){}), 8))", read_elem(&self.scope, prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pbR.ReadBytes(pbR.Count({}, 8))", self.scope.expr(e)),
            _ => "pbR.ReadBytes(pbR.RemainingBits / 8)".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("{} = pbR.Utf8({}, {});", self.scope.field(m), raw, padded));
        } else {
            out.line(format!("{} = pbR.Text({}, {}, {});", self.scope.field(m), raw, m.encoding.id(), padded));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbR.SkipBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbR.SkipBits((long)pbR.Count({}, {}) * {});", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pbR.SkipBits(pbR.RemainingBits);"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("{} = {};", self.scope.field(m), read_elem(&self.scope, codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = self.scope.field(m);
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("pbR.Count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = pbR.{}({});", target, self.read_bytes(), n));
                } else {
                    out.open("{");
                    out.line(format!("int pbN = {};", n));
                    out.line(format!("var pbA = new {}[pbN];", scalar_type(ty)));
                    out.line("for (int pbI = 0; pbI < pbN; pbI++)");
                    out.open("{");
                    out.line("pbR.AtIndex(pbI);");
                    out.line(format!("pbA[pbI] = {};", read_elem(&self.scope, codec, ty)));
                    out.close("}");
                    out.line(format!("{} = pbA;", target));
                    out.close("}");
                }
            }
            Count::Terminated { term, optional } => {
                let read = if self.zero_copy { "ReadUntilMemory" } else { "ReadUntil" };
                out.line(format!("{} = pbR.{}({}, {});", target, read, byte_list(term), optional))
            }
            Count::Until(cond) => {
                out.open("{");
                out.line(format!("var pbL = new List<{}>();", scalar_type(ty)));
                out.line("while (pbR.RemainingBits > 0)");
                out.open("{");
                out.line("pbR.AtIndex(pbL.Count);");
                out.line(format!("var pbLast = {};", read_elem(&self.scope, codec, ty)));
                out.line("pbL.Add(pbLast);");
                out.line(format!("if ({}) break;", self.scope.expr(cond)));
                out.close("}");
                out.line(format!("{} = pbL.ToArray();", target));
                out.close("}");
            }
            Count::Remaining => {
                if ty.is_byte() {
                    out.line(format!("{} = pbR.{}(pbR.RemainingBits / 8);", target, self.read_bytes()));
                } else {
                    out.open("{");
                    out.line(format!("var pbL = new List<{}>();", scalar_type(ty)));
                    out.line("while (pbR.RemainingBits > 0)");
                    out.open("{");
                    out.line("pbR.AtIndex(pbL.Count);");
                    out.line(format!("pbL.Add({});", read_elem(&self.scope, codec, ty)));
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
