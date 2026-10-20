//! Rust decoder statements.

use super::expr::store_value;
use super::naming::{Rust, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, TExpr, ValueType};

/// Expression that reads one element.
fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let signed = ty.is_signed();
    let width = match ty {
        ValueType::Int { width, .. } => *width,
        _ => 0,
    };
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
        Codec::Bits { width } => format!("pb_r.read_bits({})?", width),
        Codec::Float { width: 32, endian } => {
            return format!("f32::from_bits(pb_r.read_uint(4, {})? as u32)", Rust::little(endian));
        }
        Codec::Float { endian, .. } => return format!("f64::from_bits(pb_r.read_uint(8, {})?)", Rust::little(endian)),
        Codec::Mac => return "pb_r.read_mac()?".into(),
        Codec::Packet(n) => return format!("{}::decode_from(pb_r)?", n),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    if signed { format!("pb_sext({}, {}) as {}", raw, width, st) } else { format!("{} as {}", raw, st) }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Rust>,
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
        out.line(format!("pb_r.at(\"{}\");", field));
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_r.skip_bits(pb_pad(pb_r.position_bits() - pb_start, {}))?;", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {};", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pb_r.read_cstring()?".to_string(),
            (StrMode::Prefixed { prefix, .. }, _) => {
                let len = read_elem(prefix, &PREFIX_LEN);
                format!("{{ let pb_n = {} as i64; pb_r.read_bytes(pb_r.count(pb_n, 8)?)? }}", len)
            }
            (_, Some(Count::Expr(e))) => format!("pb_r.read_bytes(pb_r.count({}, 8)?)?", self.scope.expr(e)),
            _ => "pb_r.read_bytes(pb_r.remaining_bits() / 8)?".to_string(),
        };
        let raw = if *mode == StrMode::Padded { format!("pb_until_nul({})", raw) } else { raw };
        out.open("{");
        out.line(format!("let pb_t = {};", raw));
        out.line(format!("p.{} = pb_r.utf8(pb_t)?;", ident(&m.name)));
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_r.skip_bits({})?;", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_r.skip_bits(pb_r.count({}, {})? * {})?;", self.scope.expr(e), bits, bits));
            }
            Some(Count::Remaining) => out.line("pb_r.skip_bits(pb_r.remaining_bits())?;"),
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {};", ident(&m.name), read_elem(codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        let n = match count {
            Count::Expr(e) => format!("pb_r.count({}, {})?", self.scope.expr(e), ebits),
            Count::Remaining => String::new(),
        };
        if ty.is_byte() {
            match count {
                Count::Expr(_) => out.line(format!("{} = pb_r.read_bytes({})?;", target, n)),
                Count::Remaining => out.line(format!("{} = pb_r.read_bytes(pb_r.remaining_bits() / 8)?;", target)),
            }
            return;
        }
        match count {
            Count::Expr(_) => {
                out.open("{");
                out.line(format!("let pb_n = {};", n));
                out.line(format!("{} = Vec::with_capacity(pb_n);", target));
                out.open("for pb_i in 0..pb_n {");
                out.line("pb_r.at_index(pb_i);");
                out.line(format!("{}.push({});", target, read_elem(codec, ty)));
                out.close("}");
                out.close("}");
            }
            Count::Remaining => {
                out.open("while pb_r.remaining_bits() > 0 {");
                out.line(format!("pb_r.at_index({}.len());", target));
                out.line(format!("{}.push({});", target, read_elem(codec, ty)));
                out.close("}");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
            _ => format!("pb_r.read_bits({})?", container_width),
        };
        out.line(format!("let pb_c: u64 = {};", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let st = scalar_type(&m.ty);
            let bits = format!("((pb_c >> {}) & 0x{:x})", part.shift, mask(part.width));
            let value = if part.signed {
                format!("pb_sext({}, {}) as {}", bits, part.width, st)
            } else {
                format!("{} as {}", bits, st)
            };
            out.line(format!("p.{} = {};", ident(&m.name), value));
        }
        out.close("}");
    }
}
