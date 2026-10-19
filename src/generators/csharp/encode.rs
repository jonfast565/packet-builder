//! C# encoder statements.

use super::naming::CSharp;
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str, field: &str) {
    match ty {
        ValueType::Int { width, signed } if ty.needs_range_check() => {
            if *signed {
                out.line(format!("Pb.CheckI((long){}, {}, \"{}\");", v, width, field));
            } else {
                out.line(format!("Pb.CheckU((ulong){}, {}, \"{}\");", v, width, field));
            }
        }
        ValueType::Mac => out.line(format!("Pb.CheckLen({}.Length, 6, \"{}\");", v, field)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pbW.WriteUint(unchecked((ulong){}), {}, {});", v, nbytes, CSharp::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pbW.WriteBits(unchecked((ulong){}), {});", v, width)),
        Codec::Float { width: 32, endian } => out.line(format!(
            "pbW.WriteUint(unchecked((uint)BitConverter.SingleToInt32Bits({})), 4, {});",
            v,
            CSharp::little(endian)
        )),
        Codec::Float { endian, .. } => out.line(format!(
            "pbW.WriteUint(unchecked((ulong)BitConverter.DoubleToInt64Bits({})), 8, {});",
            v,
            CSharp::little(endian)
        )),
        Codec::Mac => out.line(format!("pbW.WriteBytes({});", v)),
        Codec::Packet(_) => out.line(format!("{}.EncodeTo(pbW);", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, CSharp>,
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
        out.line(format!("pbW.WriteZeroBits(Pb.Pad(pbW.PositionBits - pbStart, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        out.line(format!("var pbB = Pb.Utf8Bytes({});", self.scope.field(m)));
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("Pb.CheckNoNul(pbB, \"{}\");", m.name));
                out.line("pbW.WriteBytes(pbB);");
                out.line("pbW.WriteBytes(new byte[1]);");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("Pb.CheckU((ulong)pbB.Length, {}, \"{}\");", width, m.name));
                write_elem(out, prefix, &PREFIX_LEN, "pbB.Length", &m.name);
                out.line("pbW.WriteBytes(pbB);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("long pbN = {};", self.scope.expr(e)));
                out.line(format!("Pb.CheckFits(pbB.Length, pbN, \"{}\");", m.name));
                out.line("pbW.WriteBytes(pbB);");
                out.line("pbW.WriteZeroBits((pbN - pbB.Length) * 8);");
            }
            (_, Some(Count::Expr(e))) => {
                out.line(format!("Pb.CheckLen(pbB.Length, {}, \"{}\");", self.scope.expr(e), m.name));
                out.line("pbW.WriteBytes(pbB);");
            }
            _ => out.line("pbW.WriteBytes(pbB);"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbW.WriteZeroBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbW.WriteZeroBits(Math.Max({}, 0L) * {});", self.scope.expr(e), bits))
            }
            Some(Count::Remaining) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &self.scope.field(m), &m.name);
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.scope.field(m);
        if let Count::Expr(e) = count {
            out.line(format!("Pb.CheckLen({}.Length, {}, \"{}\");", place, self.scope.expr(e), m.name));
        }
        if ty.is_byte() {
            out.line(format!("pbW.WriteBytes({});", place));
        } else {
            out.line(format!("foreach (var pbV in {})", place));
            out.open("{");
            write_elem(out, codec, ty, "pbV", &m.name);
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("ulong pbC = 0;");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = self.scope.field(m);
            if part.signed {
                out.line(format!("Pb.CheckI((long){}, {}, \"{}\");", place, part.width, m.name));
            } else {
                out.line(format!("Pb.CheckU((ulong){}, {}, \"{}\");", place, part.width, m.name));
            }
            out.line(format!("pbC |= (unchecked((ulong){}) & 0x{:x}UL) << {};", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pbW.WriteUint(pbC, {}, {});", nbytes, CSharp::little(endian)))
            }
            _ => out.line(format!("pbW.WriteBits(pbC, {});", container_width)),
        }
        out.close("}");
    }
}
