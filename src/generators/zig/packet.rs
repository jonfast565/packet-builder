//! A Zig struct with `decode`/`encode`/`deinit` for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{default_value, ident, member_type, owns_memory};
use crate::generators::common::{Out, StepEmitter, member_category};
use crate::ir::{Packet, ValueType};

pub fn emit_packet(out: &mut Out, p: &Packet) {
    let name = &p.name;
    out.open(format!("pub const {} = struct {{", name));
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/// Values from `{}`.", ident(cat)));
        }
        out.line(format!("{}: {} = {},", ident(&m.name), member_type(m), default_value(m)));
    }
    if !p.members.is_empty() {
        out.line("");
    }
    let allocates = p.members.iter().any(owns_memory);

    // deinit
    out.line("/// Free memory owned by a decoded value.");
    out.open(format!("pub fn deinit(self: *{}, allocator: std.mem.Allocator) void {{", name));
    if !allocates {
        out.line("_ = self;");
        out.line("_ = allocator;");
    }
    for m in p.members.iter().filter(|m| owns_memory(m)) {
        let id = ident(&m.name);
        match (&m.array, &m.ty) {
            (Some(_), ValueType::Packet(_)) => {
                out.line(format!("for (self.{}) |*pb_e| @constCast(pb_e).deinit(allocator);", id));
                out.line(format!("allocator.free(self.{});", id));
            }
            (Some(_), _) | (None, ValueType::Str) => out.line(format!("allocator.free(self.{});", id)),
            _ => out.line(format!("self.{}.deinit(allocator);", id)),
        }
        let empty = match (&m.array, &m.ty) {
            (Some(_), _) => "&.{}",
            (None, ValueType::Str) => "\"\"",
            _ => ".{}",
        };
        out.line(format!("self.{} = {};", id, empty));
    }
    out.close("}");
    out.line("");

    // decode
    out.line("/// Decode from the start of `data`. Trailing bytes are ignored.");
    out.open(format!("pub fn decode(allocator: std.mem.Allocator, data: []const u8) PbError!{} {{", name));
    out.line("var pb_r = PbReader.init(data);");
    out.line("return decodeFrom(allocator, &pb_r);");
    out.close("}");
    out.line("");

    let mut body = Out::new("    ");
    body.push();
    body.push();
    Decoder::new(p).emit_steps(&mut body);
    out.open(format!("pub fn decodeFrom(allocator: std.mem.Allocator, pb_r: *PbReader) PbError!{} {{", name));
    if !uses(&body.buf, "allocator") {
        out.line("_ = allocator;");
    }
    if uses(&body.buf, "p") {
        out.line(format!("var p: {} = .{{}};", name));
        if allocates {
            out.line("errdefer p.deinit(allocator);");
        }
        if p.needs_start(false) {
            out.line("const pb_start = pb_r.positionBits();");
        }
    } else {
        out.line(format!("const p: {} = .{{}};", name));
    }
    out.line(format!("try pb_r.enter(\"{}\");", name));
    out.pop();
    out.buf.push_str(&body.buf);
    out.push();
    out.line("pb_r.leave();");
    out.line("return p;");
    out.close("}");
    out.line("");

    // encode
    out.line("/// Encode into a new buffer owned by the caller.");
    out.open(format!("pub fn encode(self: *const {}, allocator: std.mem.Allocator) PbError![]u8 {{", name));
    out.line("var pb_w = PbWriter.init(allocator);");
    out.line("errdefer pb_w.deinit();");
    out.line("try self.encodeTo(&pb_w);");
    out.line("return pb_w.toOwnedSlice();");
    out.close("}");
    out.line("");

    let encoder = Encoder::new(p);
    let mut body = Out::new("    ");
    body.push();
    body.push();
    for (m, e) in p.encode_calc_members() {
        encoder.define_local(&mut body, m, e);
    }
    encoder.emit_steps(&mut body);
    out.open(format!("pub fn encodeTo(self: *const {}, pb_w: *PbWriter) PbError!void {{", name));
    if uses(&body.buf, "p") {
        out.line("const p = self;");
    } else {
        out.line("_ = self;");
    }
    if p.needs_start(true) {
        out.line("const pb_start = pb_w.positionBits();");
    }
    out.line(format!("try pb_w.enter(\"{}\");", name));
    out.pop();
    out.buf.push_str(&body.buf);
    out.push();
    out.line("pb_w.leave();");
    out.close("}");
    out.close("};");
}

/// Whether `code` mentions the identifier `name` (Zig rejects unused locals).
fn uses(code: &str, name: &str) -> bool {
    let bytes = code.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    code.match_indices(name).any(|(i, _)| {
        let before = i == 0 || !is_ident(bytes[i - 1]);
        let end = i + name.len();
        let after = end >= bytes.len() || !is_ident(bytes[end]);
        before && after && (i == 0 || bytes[i - 1] != b'.')
    })
}
