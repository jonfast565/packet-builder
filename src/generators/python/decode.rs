//! Python decoder statements.

use super::expr::store_value;
use super::naming::{Python, float_format, ident};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, TExpr, ValueType};

fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})", nbytes, Python::little(endian)),
        Codec::Bits { width } => format!("pb_r.read_bits({})", width),
        Codec::Float { width, endian } => {
            return format!("struct.unpack(\"{}\", pb_r.read_bytes({}))[0]", float_format(*width, endian), width / 8);
        }
        Codec::Mac => return "pb_r.read_bytes(6)".into(),
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
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_r.at(\"{}\")", field));
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
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pb_r.read_bytes(pb_r.count({}, 8))", read_elem(prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pb_r.read_bytes(pb_r.count({}, 8))", self.scope.expr(e)),
            _ => "pb_r.read_bytes(pb_r.remaining_bits() // 8)".to_string(),
        };
        let raw = if *mode == StrMode::Padded { format!("_pb_until_nul({})", raw) } else { raw };
        out.line(format!("p.{} = pb_r.utf8({})", ident(&m.name), raw));
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_r.skip_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_r.skip_bits(pb_r.count({}, {}) * {})", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pb_r.skip_bits(pb_r.remaining_bits())"),
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
