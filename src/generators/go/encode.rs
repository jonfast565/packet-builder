//! Go encoder statements. Like decoding, the writer records the first error.

use super::naming::{Go, field_name};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str, field: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("pbW.CheckI(int64({}), {}, \"{}\")", v, width, field));
        } else {
            out.line(format!("pbW.CheckU(uint64({}), {}, \"{}\")", v, width, field));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.WriteUint(uint64({}), {}, {})", v, nbytes, Go::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.WriteBits(uint64({}), {})", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pbW.WriteUint(uint64(math.Float32bits({})), 4, {})", v, Go::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pbW.WriteUint(math.Float64bits({}), 8, {})", v, Go::little(endian)))
        }
        Codec::Mac => out.line(format!("pbW.WriteBytes({}[:])", v)),
        Codec::Packet(_) => out.line(format!("{}.EncodeTo(pbW)", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Go>,
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
        out.line(format!("pbW.WriteZeroBits(int64(pbPad(pbW.PositionBits()-pbStart, {})))", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        out.line(format!("pbW.CheckUTF8(p.{}, \"{}\")", field_name(&m.name), m.name));
        out.line(format!("pbB := []byte(p.{})", field_name(&m.name)));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("pbW.CheckNoNul(pbB, \"{}\")", m.name));
                out.line("pbW.WriteBytes(pbB)");
                out.line("pbW.WriteBytes([]byte{0})");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pbW.CheckU(uint64(len(pbB)), {}, \"{}\")", width, m.name));
                write_elem(out, prefix, &PREFIX_LEN, "len(pbB)", &m.name);
                out.line("pbW.WriteBytes(pbB)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("pbN := {}", self.scope.expr(e)));
                out.line(format!("pbW.CheckFits(len(pbB), pbN, \"{}\")", m.name));
                out.line("pbW.WriteBytes(pbB)");
                out.line("pbW.WriteZeroBits((pbN - int64(len(pbB))) * 8)");
            }
            (_, Some(Count::Expr(e))) => {
                out.line(format!("pbW.CheckLen(len(pbB), {}, \"{}\")", self.scope.expr(e), m.name));
                out.line("pbW.WriteBytes(pbB)");
            }
            _ => out.line("pbW.WriteBytes(pbB)"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.WriteZeroBits({})", bits)),
            Some(Count::Expr(e)) => out.line(format!("pbW.WriteZeroBits(pbMax({}, 0) * {})", self.scope.expr(e), bits)),
            Some(Count::Remaining) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &format!("p.{}", field_name(&m.name)), &m.name);
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", field_name(&m.name));
        if let Count::Expr(e) = count {
            out.line(format!("pbW.CheckLen(len({}), {}, \"{}\")", place, self.scope.expr(e), m.name));
        }
        if ty.is_byte() {
            out.line(format!("pbW.WriteBytes({})", place));
        } else {
            out.open(format!("for pbI := range {} {{", place));
            write_elem(out, codec, ty, &format!("{}[pbI]", place), &m.name);
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("var pbC uint64");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", field_name(&m.name));
            if part.signed {
                out.line(format!("pbW.CheckI(int64({}), {}, \"{}\")", place, part.width, m.name));
            } else {
                out.line(format!("pbW.CheckU(uint64({}), {}, \"{}\")", place, part.width, m.name));
            }
            out.line(format!("pbC |= (uint64({}) & 0x{:x}) << {}", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.WriteUint(pbC, {}, {})", nbytes, Go::little(endian)))
            }
            _ => out.line(format!("pbW.WriteBits(pbC, {})", container_width)),
        }
        out.close("}");
    }
}
