//! Python decoder statements.

use super::expr::store_value;
use super::naming::{Python, float_format, ident};
use crate::generators::common::union::{PY_LOGIC, arm_test};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, TextEncoding, ValueType};

/// `b"\x0d\x0a"`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: String = bytes.iter().map(|b| format!("\\x{:02x}", b)).collect();
    format!("b\"{}\"", items)
}

fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})", nbytes, Python::little(endian)),
        Codec::Bits { width } => format!("pb_r.read_bits({})", width),
        Codec::Float { width, endian } => {
            return format!("struct.unpack(\"{}\", pb_r.read_bytes({}))[0]", float_format(*width, endian), width / 8);
        }
        Codec::Mac => return "pb_r.read_bytes(6)".into(),
        Codec::Varint(k) => format!("pb_r.read_varint({})", k.id()),
        Codec::Packet(n) => return format!("{}.decode_from(pb_r)", n),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("_pb_sext({}, {})", raw, width),
        _ => raw,
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Python>,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode) }
    }

    /// Expression that decodes the value of `arm`.
    fn arm_value(&self, arm: &Arm) -> String {
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => "None".into(),
            (Some(_), _, Some(Count::Expr(e))) => format!("pb_r.read_bytes(pb_r.count({}, 8))", self.scope.expr(e)),
            (Some(_), _, Some(Count::Remaining)) => "pb_r.read_bytes(pb_r.remaining_bits() // 8)".into(),
            (Some(ty), Some(codec), None) => read_elem(codec, ty),
            _ => "None".into(),
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.open(format!("if not {}:", self.scope.expr(cond)));
        out.line(format!("raise pb_r.error(PbError.CONSTRAINT, {})", string_literal(message)));
        out.pop();
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_r.at(\"{}\")", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = format!("p.{}", ident(&m.name));
        out.line(format!("pb_sel = {}", self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "pb_sel", &PY_LOGIC).unwrap_or_else(|| "True".into());
            out.open(format!("{} {}:", if first { "if" } else { "elif" }, test));
            out.line(format!("{} = {}(\"{}\", {})", place, u, arm.name, self.arm_value(arm)));
            out.pop();
            first = false;
        }
        let default = arms.iter().find(|a| a.default);
        if !first {
            out.open("else:");
        }
        match default {
            Some(arm) => out.line(format!("{} = {}(\"{}\", {})", place, u, arm.name, self.arm_value(arm))),
            None => out.line(format!("raise pb_r.error(PbError.INVALID, \"no arm of `{}` for %d\" % pb_sel)", m.name)),
        }
        if !first {
            out.pop();
        }
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("pb_win{} = pb_r.push_limit({})", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pb_r.pop_limit(pb_win{}, {})", id, if exact { "True" } else { "False" }));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pb_r.position_bits()", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.open(format!("if _pb_wrap(p.{}) != {}:", ident(&m.name), self.scope.expr(value)));
        out.line(format!(
            "raise pb_r.error(PbError.MISMATCH, {})",
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
        out.pop();
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_r.skip_bits(_pb_pad(pb_r.position_bits() - pb_start, {}))", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {}", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pb_r.read_cstring()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pb_r.read_until({}, {})", byte_list(term), Python::flag(*optional))
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pb_r.read_bytes(pb_r.count({}, 8))", read_elem(prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pb_r.read_bytes(pb_r.count({}, 8))", self.scope.expr(e)),
            _ => "pb_r.read_bytes(pb_r.remaining_bits() // 8)".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        if m.encoding == TextEncoding::Utf8 {
            let raw = if padded { format!("_pb_until_nul({})", raw) } else { raw };
            out.line(format!("p.{} = pb_r.utf8({})", ident(&m.name), raw));
        } else {
            out.line(format!(
                "p.{} = pb_r.text({}, {}, {})",
                ident(&m.name),
                raw,
                m.encoding.id(),
                Python::flag(padded)
            ));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_r.skip_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_r.skip_bits(pb_r.count({}, {}) * {})", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pb_r.skip_bits(pb_r.remaining_bits())"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {}", ident(&m.name), read_elem(codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("pb_r.count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = pb_r.read_bytes({})", target, n));
                } else {
                    out.line(format!("{} = []", target));
                    out.open(format!("for pb_i in range({}):", n));
                    out.line("pb_r.at_index(pb_i)");
                    out.line(format!("{}.append({})", target, read_elem(codec, ty)));
                    out.pop();
                }
            }
            Count::Terminated { term, optional } => {
                out.line(format!("{} = pb_r.read_until({}, {})", target, byte_list(term), Python::flag(*optional)))
            }
            Count::Until(cond) => {
                out.line(format!("{} = []", target));
                out.open("while pb_r.remaining_bits() > 0:");
                out.line(format!("pb_r.at_index(len({}))", target));
                out.line(format!("pb_last = {}", read_elem(codec, ty)));
                out.line(format!("{}.append(pb_last)", target));
                out.open(format!("if {}:", self.scope.expr(cond)));
                out.line("break");
                out.pop();
                out.pop();
            }
            Count::Remaining => {
                if ty.is_byte() {
                    out.line(format!("{} = pb_r.read_bytes(pb_r.remaining_bits() // 8)", target));
                } else {
                    out.line(format!("{} = []", target));
                    out.open("while pb_r.remaining_bits() > 0:");
                    out.line(format!("pb_r.at_index(len({}))", target));
                    out.line(format!("{}.append({})", target, read_elem(codec, ty)));
                    out.pop();
                }
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})", nbytes, Python::little(endian)),
            _ => format!("pb_r.read_bits({})", container_width),
        };
        out.line(format!("pb_c = {}", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let bits = format!("((pb_c >> {}) & 0x{:x})", part.shift, mask(part.width));
            let v = if part.signed { format!("_pb_sext({}, {})", bits, part.width) } else { bits };
            out.line(format!("p.{} = {}", ident(&m.name), v));
        }
    }
}
