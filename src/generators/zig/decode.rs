//! Zig decoder statements.

use super::expr::store_value;
use super::naming::{Zig, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, TExpr, ValueType};

fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    match codec {
        Codec::Bytes { nbytes, endian } => {
            format!("pbFromBits({}, try pb_r.readUint({}, {}))", st, nbytes, Zig::little(endian))
        }
        Codec::Bits { width } => format!("pbFromBits({}, try pb_r.readBits({}))", st, width),
        Codec::Float { width: 32, endian } => {
            format!("@as(f32, @bitCast(@as(u32, @truncate(try pb_r.readUint(4, {})))))", Zig::little(endian))
        }
        Codec::Float { endian, .. } => format!("@as(f64, @bitCast(try pb_r.readUint(8, {})))", Zig::little(endian)),
        Codec::Mac => "try pb_r.readMac()".into(),
        Codec::Packet(n) => format!("try {}.decodeFrom(allocator, pb_r)", n),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Zig>,
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

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("try pb_r.skipBits(pbPad(pb_r.positionBits() - pb_start, {}));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {};", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let target = format!("p.{}", ident(&m.name));
        let padded = *mode == StrMode::Padded;
        match (mode, array) {
            (StrMode::CString, _) => out.line(format!("{} = try pb_r.readCText(allocator);", target)),
            (StrMode::Prefixed { prefix, .. }, _) => {
                out.open("{");
                out.line(format!("const pb_n = {};", read_elem(prefix, &PREFIX_LEN)));
                out.line(format!(
                    "{} = try pb_r.readText(allocator, try pb_r.count(@bitCast(pb_n), 8), false);",
                    target
                ));
                out.close("}");
            }
            (_, Some(Count::Expr(e))) => out.line(format!(
                "{} = try pb_r.readText(allocator, try pb_r.count({}, 8), {});",
                target,
                self.scope.expr(e),
                padded
            )),
            _ => out.line(format!("{} = try pb_r.readText(allocator, pb_r.remainingBits() / 8, {});", target, padded)),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("try pb_r.skipBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("try pb_r.skipBits((try pb_r.count({}, {})) * {});", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("try pb_r.skipBits(pb_r.remainingBits());"),
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {};", ident(&m.name), read_elem(codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("try pb_r.count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = try pb_r.readBytes(allocator, {});", target, n));
                } else {
                    out.open("{");
                    out.line(format!("const pb_a = try allocator.alloc({}, {});", scalar_type(ty), n));
                    out.line(format!(
                        "@memset(pb_a, {});",
                        if matches!(ty, ValueType::Packet(_)) { ".{}" } else { "std.mem.zeroes(@TypeOf(pb_a[0]))" }
                    ));
                    out.line(format!("{} = pb_a;", target));
                    out.line(format!("for (pb_a) |*pb_e| pb_e.* = {};", read_elem(codec, ty)));
                    out.close("}");
                }
            }
            Count::Remaining => {
                if ty.is_byte() {
                    out.line(format!("{} = try pb_r.readBytes(allocator, pb_r.remainingBits() / 8);", target));
                } else {
                    out.open("{");
                    out.line(format!("var pb_l = std.ArrayList({}).init(allocator);", scalar_type(ty)));
                    if matches!(ty, ValueType::Packet(_)) {
                        out.open("errdefer {");
                        out.line("for (pb_l.items) |*pb_e| pb_e.deinit(allocator);");
                        out.line("pb_l.deinit();");
                        out.close("}");
                    } else {
                        out.line("errdefer pb_l.deinit();");
                    }
                    out.line(format!("while (pb_r.remainingBits() > 0) try pb_l.append({});", read_elem(codec, ty)));
                    out.line(format!("{} = try pb_l.toOwnedSlice();", target));
                    out.close("}");
                }
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("try pb_r.readUint({}, {})", nbytes, Zig::little(endian)),
            _ => format!("try pb_r.readBits({})", container_width),
        };
        out.line(format!("const pb_c = {};", raw));
        if parts.is_empty() {
            out.line("_ = pb_c;");
        }
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!(
                "p.{} = pbFromBits({}, (pb_c >> {}) & 0x{:x});",
                ident(&m.name),
                scalar_type(&m.ty),
                part.shift,
                mask(part.width)
            ));
        }
        out.close("}");
    }
}
