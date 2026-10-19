//! Python encoder statements.

use super::naming::{Python, float_format, ident};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str, field: &str) {
    match ty {
        ValueType::Int { width, signed: true } => out.line(format!("_pb_check_i({}, {}, \"{}\")", v, width, field)),
        ValueType::Int { width, signed: false } => out.line(format!("_pb_check_u({}, {}, \"{}\")", v, width, field)),
        ValueType::Mac => out.line(format!("_pb_check_len(len({}), 6, \"{}\")", v, field)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pb_w.write_uint({}, {}, {})", v, nbytes, Python::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pb_w.write_bits({}, {})", v, width)),
        Codec::Float { width, endian } => {
            out.line(format!("pb_w.write_bytes(struct.pack(\"{}\", {}))", float_format(*width, endian), v));
        }
        Codec::Mac => out.line(format!("pb_w.write_bytes(bytes({}))", v)),
        Codec::Packet(_) => out.line(format!("{}.encode_to(pb_w)", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Python>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_w.write_zero_bits(_pb_pad(pb_w.position_bits() - pb_start, {}))", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.line(format!("pb_b = _pb_utf8_bytes(p.{}, \"{}\")", ident(&m.name), m.name));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("_pb_check_no_nul(pb_b, \"{}\")", m.name));
                out.line("pb_w.write_bytes(pb_b + b\"\\0\")");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("_pb_check_u(len(pb_b), {}, \"{}\")", width, m.name));
                write_elem(out, prefix, &PREFIX_LEN, "len(pb_b)", &m.name);
                out.line("pb_w.write_bytes(pb_b)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("pb_n = {}", self.scope.expr(e)));
                out.line(format!("_pb_check_fits(len(pb_b), pb_n, \"{}\")", m.name));
                out.line("pb_w.write_bytes(pb_b + bytes(pb_n - len(pb_b)))");
            }
            (_, Some(Count::Expr(e))) => {
                out.line(format!("_pb_check_len(len(pb_b), {}, \"{}\")", self.scope.expr(e), m.name));
                out.line("pb_w.write_bytes(pb_b)");
            }
            _ => out.line("pb_w.write_bytes(pb_b)"),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_w.write_zero_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_w.write_zero_bits(max({}, 0) * {})", self.scope.expr(e), bits))
            }
            Some(Count::Remaining) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &format!("p.{}", ident(&m.name)), &m.name);
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count {
            out.line(format!("_pb_check_len(len({}), {}, \"{}\")", place, self.scope.expr(e), m.name));
        }
        if ty.is_byte() {
            out.line(format!("pb_w.write_bytes(bytes({}))", place));
        } else {
            out.open(format!("for pb_v in {}:", place));
            write_elem(out, codec, ty, "pb_v", &m.name);
            out.pop();
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.line("pb_c = 0");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", ident(&m.name));
            if part.signed {
                out.line(format!("_pb_check_i({}, {}, \"{}\")", place, part.width, m.name));
            } else {
                out.line(format!("_pb_check_u({}, {}, \"{}\")", place, part.width, m.name));
            }
            out.line(format!("pb_c |= ({} & 0x{:x}) << {}", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pb_w.write_uint(pb_c, {}, {})", nbytes, Python::little(endian)))
            }
            _ => out.line(format!("pb_w.write_bits(pb_c, {})", container_width)),
        }
    }
}
