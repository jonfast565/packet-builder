//! Rust encoder statements.

use super::naming::{Rust, ident};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, ValueType};

/// Statements that write one element held in `v`.
fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str, field: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("pb_check_i({} as i64, {}, \"{}\")?;", v, width, field));
        } else {
            out.line(format!("pb_check_u({} as u64, {}, \"{}\")?;", v, width, field));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pb_w.write_uint({} as u64, {}, {});", v, nbytes, Rust::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pb_w.write_bits({} as u64, {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pb_w.write_uint({}.to_bits() as u64, 4, {});", v, Rust::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pb_w.write_uint({}.to_bits(), 8, {});", v, Rust::little(endian)))
        }
        Codec::Mac => out.line(format!("pb_w.write_bytes(&{});", v)),
        Codec::Packet(_) => out.line(format!("{}.encode_to(pb_w)?;", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Rust>,
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
        out.line(format!("pb_w.write_zero_bits(pb_pad(pb_w.position_bits() - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        out.line(format!("let pb_b = p.{}.as_bytes();", ident(&m.name)));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("pb_check_no_nul(pb_b, \"{}\")?;", m.name));
                out.line("pb_w.write_bytes(pb_b);");
                out.line("pb_w.write_bytes(&[0]);");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pb_check_u(pb_b.len() as u64, {}, \"{}\")?;", width, m.name));
                write_elem(out, prefix, &PREFIX_LEN, "pb_b.len()", &m.name);
                out.line("pb_w.write_bytes(pb_b);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("let pb_n = {};", self.scope.expr(e)));
                out.line(format!("pb_check_fits(pb_b.len(), pb_n, \"{}\")?;", m.name));
                out.line("pb_w.write_bytes(pb_b);");
                out.line("pb_w.write_zero_bits((pb_n as usize - pb_b.len()) * 8);");
            }
            (_, Some(Count::Expr(e))) => {
                out.line(format!("pb_check_len(pb_b.len(), {}, \"{}\")?;", self.scope.expr(e), m.name));
                out.line("pb_w.write_bytes(pb_b);");
            }
            _ => out.line("pb_w.write_bytes(pb_b);"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_w.write_zero_bits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_w.write_zero_bits(({}).max(0) as usize * {});", self.scope.expr(e), bits))
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
            out.line(format!("pb_check_len({}.len(), {}, \"{}\")?;", place, self.scope.expr(e), m.name));
        }
        if ty.is_byte() {
            out.line(format!("pb_w.write_bytes(&{});", place));
        } else {
            out.open(format!("for pb_v in {}.iter() {{", place));
            let v = match codec {
                Codec::Packet(_) => "pb_v",
                _ => "*pb_v",
            };
            write_elem(out, codec, ty, &format!("({})", v), &m.name);
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("let mut pb_c: u64 = 0;");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", ident(&m.name));
            if part.signed {
                out.line(format!("pb_check_i({} as i64, {}, \"{}\")?;", place, part.width, m.name));
            } else {
                out.line(format!("pb_check_u({} as u64, {}, \"{}\")?;", place, part.width, m.name));
            }
            out.line(format!("pb_c |= (({} as u64) & 0x{:x}) << {};", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pb_w.write_uint(pb_c, {}, {});", nbytes, Rust::little(endian)))
            }
            _ => out.line(format!("pb_w.write_bits(pb_c, {});", container_width)),
        }
        out.close("}");
    }
}
