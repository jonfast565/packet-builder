//! Zig encoder statements. Range checks are not needed: exact-width fields
//! cannot hold out-of-range values.

use super::naming::{Zig, ident};
use crate::generators::common::{Dialect, Mode, Out, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, v: &str) {
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("try pb_w.writeUint(pbToBits({}), {}, {});", v, nbytes, Zig::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("try pb_w.writeBits(pbToBits({}), {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("try pb_w.writeUint(@as(u32, @bitCast({})), 4, {});", v, Zig::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("try pb_w.writeUint(@as(u64, @bitCast({})), 8, {});", v, Zig::little(endian)))
        }
        Codec::Mac => out.line(format!("try pb_w.writeBytes(&{});", v)),
        Codec::Packet(_) => out.line(format!("try {}.encodeTo(pb_w);", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Zig>,
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
        out.line(format!("try pb_w.writeZeroBits(@intCast(pbPad(pb_w.positionBits() - pb_start, {})));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let s = format!("p.{}", ident(&m.name));
        out.line(format!("try pbCheckText({}, {});", s, !matches!(mode, StrMode::CString)));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("try pb_w.writeBytes({});", s));
                out.line("try pb_w.writeBits(0, 8);");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("try pbCheckPrefix({}.len, {});", s, width));
                write_elem(out, prefix, &format!("@as(u64, {}.len)", s));
                out.line(format!("try pb_w.writeBytes({});", s));
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.open("{");
                out.line(format!("const pb_n = {};", self.scope.expr(e)));
                out.line(format!("try pbCheckFits({}.len, pb_n);", s));
                out.line(format!("try pb_w.writeBytes({});", s));
                out.line(format!("try pb_w.writeZeroBits((pb_n - @as(i64, @intCast({}.len))) * 8);", s));
                out.close("}");
            }
            (_, Some(Count::Expr(e))) => {
                out.line(format!("try pbCheckLen({}.len, {});", s, self.scope.expr(e)));
                out.line(format!("try pb_w.writeBytes({});", s));
            }
            _ => out.line(format!("try pb_w.writeBytes({});", s)),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("try pb_w.writeZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("try pb_w.writeZeroBits(@max({}, 0) *% {});", self.scope.expr(e), bits))
            }
            Some(Count::Remaining) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, _ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, &format!("p.{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count {
            out.line(format!("try pbCheckLen({}.len, {});", place, self.scope.expr(e)));
        }
        if ty.is_byte() {
            out.line(format!("try pb_w.writeBytes({});", place));
        } else {
            out.open(format!("for ({}) |pb_v| {{", place));
            write_elem(out, codec, "pb_v");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        if parts.is_empty() {
            out.line("const pb_c: u64 = 0;");
        } else {
            out.line("var pb_c: u64 = 0;");
        }
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!("pb_c |= (pbToBits(p.{}) & 0x{:x}) << {};", ident(&m.name), mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("try pb_w.writeUint(pb_c, {}, {});", nbytes, Zig::little(endian)))
            }
            _ => out.line(format!("try pb_w.writeBits(pb_c, {});", container_width)),
        }
        out.close("}");
    }
}
