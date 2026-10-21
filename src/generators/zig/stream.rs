//! Stream helpers: `tryDecode` (a packet, or how many more bytes are
//! needed) and `frameLen` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{Zig, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = &p.name;
    out.line("");
    out.line("/// Decode from a buffer that may end mid-packet (a stream): the packet and the");
    out.line("/// bytes it took, or how many more bytes are needed at least.");
    out.open(format!("pub fn tryDecode(allocator: std.mem.Allocator, data: []const u8) PbError!PbStatus({}) {{", name));
    out.line("var pb_r = PbReader.init(data);");
    out.open("const p = decodeFrom(allocator, &pb_r) catch |err| {");
    out.line(
        "if (err == PbError.Incomplete) return .{ .incomplete = @max((pb_r.trace.diag.needed_bits + 7) / 8, 1) };",
    );
    out.line("return err;");
    out.close("};");
    out.line("return .{ .done = .{ .value = p, .consumed = (pb_r.pos + 7) / 8 } };");
    out.close("}");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line("");
        out.line("/// `tryDecode` as protocol version `version`.");
        out.open(format!(
            "pub fn tryDecodeV(allocator: std.mem.Allocator, data: []const u8, version: u32) PbError!PbStatus({}) {{",
            name
        ));
        out.line("var pb_r = PbReader.init(data);");
        out.line(format!("try pb_r.setVersion(version, {}, {});", min, latest));
        out.open("const p = decodeFrom(allocator, &pb_r) catch |err| {");
        out.line(
            "if (err == PbError.Incomplete) return .{ .incomplete = @max((pb_r.trace.diag.needed_bits + 7) / 8, 1) };",
        );
        out.line("return err;");
        out.close("};");
        out.line("return .{ .done = .{ .value = p, .consumed = (pb_r.pos + 7) / 8 } };");
        out.close("}");
    }
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Zig>::new(p, Mode::Decode);
    out.line("");
    out.line(format!("/// The packet's size from its first {} byte(s), or null until they are there.", f.header_bytes));
    out.open("pub fn frameLen(data: []const u8) PbError!?usize {");
    if f.header_bytes > 0 {
        out.line(format!("if (data.len < {}) return null;", f.header_bytes));
    } else if f.fields.is_empty() {
        out.line("_ = data;");
    }
    if !f.fields.is_empty() {
        out.line(format!("var p: {} = .{{}};", name));
    }
    for h in &f.fields {
        let m = &p.members[h.member];
        out.open("{");
        out.line("var pb_r = PbReader.init(data);");
        out.line(format!("try pb_r.skipBits({});", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("try pb_r.readUint({}, {})", nbytes, Zig::little(endian)),
            _ => format!("try pb_r.readBits({})", h.container_bits),
        };
        out.line(format!("const pb_c = {};", raw));
        out.line(format!(
            "p.{} = pbFromBits({}, (pb_c >> {}) & 0x{:x});",
            ident(&m.name),
            scalar_type(&m.ty),
            h.shift,
            mask(h.bits)
        ));
        out.close("}");
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p.{} = {};", ident(&m.name), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("const pb_n: i64 = {};", scope.expr(&f.total)));
    out.line("if (pb_n < 0) return PbError.Invalid;");
    out.line("return @intCast(pb_n);");
    out.close("}");
}
