//! Zig decoder statements.

use super::expr::store_value;
use super::naming::{Zig, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Zig>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// `&[_]u8{ 0x0d, 0x0a }`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("&[_]u8{{ {} }}", items.join(", "))
}

fn read_elem(scope: &Scope<'_, Zig>, codec: &Codec, ty: &ValueType) -> String {
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
        Codec::Varint(k) => format!("pbFromBits({}, try pb_r.readVarint({}))", st, k.id()),
        Codec::Packet(r) => format!("try {}.decodeFrom(allocator, pb_r{})", r.name, call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Zig>,
    /// Byte buffers are slices of the input.
    zero_copy: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, zero_copy: bool) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), zero_copy }
    }

    /// Reading `n` bytes into a byte buffer: a copy, or a slice of the input.
    fn read_bytes(&self, n: &str) -> String {
        if self.zero_copy {
            format!("try pb_r.bytesSlice({})", n)
        } else {
            format!("try pb_r.readBytes(allocator, {})", n)
        }
    }

    /// Expression that decodes `arm` (an anonymous union literal).
    fn arm_value(&self, arm: &Arm) -> String {
        let field = ident(&arm.name);
        let value = match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => "{}".to_string(),
            (Some(_), _, Some(Count::Expr(e))) => {
                self.read_bytes(&format!("try pb_r.count({}, 8)", self.scope.expr(e)))
            }
            (Some(_), _, Some(Count::Remaining)) => self.read_bytes("pb_r.remainingBits() / 8"),
            (Some(ty), Some(codec), None) => read_elem(&self.scope, codec, ty),
            (_, _, Some(Count::Until(_) | Count::Terminated { .. })) => {
                unreachable!("union arms have no until or term")
            }
            _ => "{}".to_string(),
        };
        format!(".{{ .{} = {} }}", field, value)
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, _message: &str) {
        out.line(format!("if (!{}) return pb_r.fail(PbError.Constraint);", self.scope.expr(cond)));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_r.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let place = format!("p.{}", ident(&m.name));
        out.open("{");
        out.line(format!("const pb_sel: i64 = {};", self.scope.expr(selector)));
        out.open("switch (pb_sel) {");
        for arm in arms.iter().filter(|a| !a.default) {
            let values: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            out.line(format!("{} => {} = {},", values.join(", "), place, self.arm_value(arm)));
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => out.line(format!("else => {} = {},", place, self.arm_value(arm))),
            None => out.line("else => return pb_r.fail(PbError.Invalid),"),
        }
        out.close("}");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("const pb_win{} = try pb_r.pushLimit({});", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("try pb_r.popLimit(pb_win{}, {});", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("const {} = pb_r.positionBits();", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if (pbI64(p.{}) != {}) return pb_r.fail(PbError.Mismatch);",
            ident(&m.name),
            self.scope.expr(value)
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("const pb_j = try pb_r.jump({}, {});", from, self.scope.expr(offset)));
        out.line(format!(
            "p.{} = try {}.decodeFrom(allocator, pb_r{});",
            ident(&m.name),
            target.name,
            call_args(&self.scope, target)
        ));
        out.line("pb_r.jumpBack(pb_j);");
        out.close("}");
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
        if m.encoding != TextEncoding::Utf8 || matches!(mode, StrMode::Terminated { .. }) {
            let raw = match (mode, array) {
                (StrMode::CString, _) => format!("try pb_r.untilSlice({}, false)", byte_list(&[0])),
                (StrMode::Terminated { term, optional }, _) => {
                    format!("try pb_r.untilSlice({}, {})", byte_list(term), optional)
                }
                (StrMode::Prefixed { prefix, .. }, _) => {
                    format!(
                        "try pb_r.bytesSlice(try pb_r.count(@bitCast({}), 8))",
                        read_elem(&self.scope, prefix, &PREFIX_LEN)
                    )
                }
                (_, Some(Count::Expr(e))) => {
                    format!("try pb_r.bytesSlice(try pb_r.count({}, 8))", self.scope.expr(e))
                }
                _ => "try pb_r.bytesSlice(pb_r.remainingBits() / 8)".to_string(),
            };
            out.line(format!("{} = try pb_r.text(allocator, {}, {}, {});", target, raw, m.encoding.id(), padded));
            return;
        }
        match (mode, array) {
            (StrMode::CString, _) => out.line(format!("{} = try pb_r.readCText(allocator);", target)),
            (StrMode::Prefixed { prefix, .. }, _) => {
                out.open("{");
                out.line(format!("const pb_n = {};", read_elem(&self.scope, prefix, &PREFIX_LEN)));
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
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {};", ident(&m.name), read_elem(&self.scope, codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("try pb_r.count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = {};", target, self.read_bytes(&n)));
                } else {
                    out.open("{");
                    out.line(format!("const pb_a = try allocator.alloc({}, {});", scalar_type(ty), n));
                    out.line(format!(
                        "@memset(pb_a, {});",
                        if matches!(ty, ValueType::Packet(_)) { ".{}" } else { "std.mem.zeroes(@TypeOf(pb_a[0]))" }
                    ));
                    out.line(format!("{} = pb_a;", target));
                    out.open("for (pb_a, 0..) |*pb_e, pb_i| {");
                    out.line("pb_r.atIndex(pb_i);");
                    out.line(format!("pb_e.* = {};", read_elem(&self.scope, codec, ty)));
                    out.close("}");
                    out.close("}");
                }
            }
            Count::Terminated { term, optional } => {
                let slice = format!("try pb_r.untilSlice({}, {})", byte_list(term), optional);
                if self.zero_copy {
                    out.line(format!("{} = {};", target, slice));
                } else {
                    out.line(format!("{} = try allocator.dupe(u8, {});", target, slice));
                }
            }
            Count::Remaining | Count::Until(_) => {
                if ty.is_byte() && matches!(count, Count::Remaining) {
                    out.line(format!("{} = {};", target, self.read_bytes("pb_r.remainingBits() / 8")));
                } else {
                    out.open("{");
                    let slice = self.zero_copy && ty.is_byte();
                    if slice {
                        out.line("const pb_from = pb_r.positionBits();");
                    }
                    out.line(format!("var pb_l = std.ArrayList({}).init(allocator);", scalar_type(ty)));
                    if matches!(ty, ValueType::Packet(_)) {
                        out.open("errdefer {");
                        out.line("for (pb_l.items) |*pb_e| pb_e.deinit(allocator);");
                        out.line("pb_l.deinit();");
                        out.close("}");
                    } else {
                        out.line("errdefer pb_l.deinit();");
                    }
                    out.open("while (pb_r.remainingBits() > 0) {");
                    out.line("pb_r.atIndex(pb_l.items.len);");
                    out.line(format!("try pb_l.append({});", read_elem(&self.scope, codec, ty)));
                    if let Count::Until(cond) = count {
                        out.line(format!("if ({}) break;", self.scope.expr(cond)));
                    }
                    out.close("}");
                    if slice {
                        // The bytes are consecutive in the input.
                        out.line("pb_l.deinit();");
                        out.line(format!("{} = pb_r.data[pb_from / 8 .. pb_r.positionBits() / 8];", target));
                    } else {
                        out.line(format!("{} = try pb_l.toOwnedSlice();", target));
                    }
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
