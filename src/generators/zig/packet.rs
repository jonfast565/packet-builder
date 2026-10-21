//! A Zig struct with `decode`/`encode`/`deinit` for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{default_value, ident, member_type, owns_memory, scalar_type};
use crate::generators::common::{Out, StepEmitter, member_category, param_var};
use crate::ir::{Arm, Module, Packet, Union, ValueType};

/// The Zig type an arm holds (`void` for an empty arm).
fn arm_type(arm: &Arm) -> String {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => "void".into(),
        (Some(_), true) => "[]const u8".into(),
        (Some(t), false) => scalar_type(t),
    }
}

/// The value an arm starts with.
fn arm_default(arm: &Arm) -> String {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => "{}".into(),
        (Some(_), true) => "&.{}".into(),
        (Some(ValueType::Packet(_)), false) => ".{}".into(),
        (Some(_), false) => "0".into(),
    }
}

/// A tagged union with a `deinit` for the arms that own memory.
pub fn emit_union(out: &mut Out, u: &Union, zero_copy: bool) {
    out.open(format!("pub const {} = union(enum) {{", u.name));
    for arm in &u.arms {
        out.line(format!("{}: {},", ident(&arm.name), arm_type(arm)));
    }
    out.line("");
    let first = &u.arms[0];
    out.line(format!("pub const pb_default: {} = .{{ .{} = {} }};", u.name, ident(&first.name), arm_default(first)));
    out.line("");
    out.line("/// Free memory owned by a decoded value.");
    out.open(format!("pub fn deinit(self: *{}, allocator: std.mem.Allocator) void {{", u.name));
    let owning: Vec<&Arm> =
        u.arms.iter().filter(|a| (a.is_bytes() && !zero_copy) || matches!(a.ty, Some(ValueType::Packet(_)))).collect();
    if owning.is_empty() {
        out.line("_ = allocator;");
    } else {
        out.open("switch (self.*) {");
        for arm in &owning {
            if arm.is_bytes() {
                out.line(format!(".{} => |pb_v| allocator.free(pb_v),", ident(&arm.name)));
            } else {
                out.line(format!(".{} => |*pb_v| pb_v.deinit(allocator),", ident(&arm.name)));
            }
        }
        if owning.len() < u.arms.len() {
            out.line("else => {},");
        }
        out.close("}");
    }
    out.line("self.* = pb_default;");
    out.close("}");
    super::json::emit_union_json(out, u);
    out.close("};");
    out.line("");
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
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
    let allocates = p.members.iter().any(|m| owns_memory(m, zero_copy));

    // deinit
    out.line("/// Free memory owned by a decoded value.");
    out.open(format!("pub fn deinit(self: *{}, allocator: std.mem.Allocator) void {{", name));
    if !allocates {
        out.line("_ = self;");
        out.line("_ = allocator;");
    }
    for m in p.members.iter().filter(|m| owns_memory(m, zero_copy)) {
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
            (Some(_), _) => "&.{}".to_string(),
            (None, ValueType::Str) => "\"\"".to_string(),
            (None, ValueType::Union(u)) => format!("{}.pb_default", u),
            _ => ".{}".to_string(),
        };
        out.line(format!("self.{} = {};", id, empty));
    }
    out.close("}");
    out.line("");

    // Parameters: `, pbp_a: u8` in signatures, `, pbp_a` in calls.
    let decl: String = p.params.iter().map(|x| format!(", {}: {}", param_var(&x.name), scalar_type(&x.ty))).collect();
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();
    // Zig rejects unused parameters.
    let touch = |out: &mut Out, body: &str| {
        for x in &p.params {
            if !uses(body, &param_var(&x.name)) {
                out.line(format!("_ = {};", param_var(&x.name)));
            }
        }
    };

    // decode
    out.line("/// Decode from the start of `data`. Trailing bytes are ignored.");
    out.open(format!("pub fn decode(allocator: std.mem.Allocator, data: []const u8{}) PbError!{} {{", decl, name));
    out.line("var pb_r = PbReader.init(data);");
    out.line(format!("return decodeFrom(allocator, &pb_r{});", pass));
    out.close("}");
    out.line("");
    let versions = p.versions.map(|_| p.version_bounds());
    if let Some((min, latest)) = versions {
        out.line(format!("/// Decode as protocol version `version` ({}..{}).", min, latest));
        out.open(format!(
            "pub fn decodeV(allocator: std.mem.Allocator, data: []const u8, version: u32{}) PbError!{} {{",
            decl, name
        ));
        out.line("var pb_r = PbReader.init(data);");
        out.line(format!("try pb_r.setVersion(version, {}, {});", min, latest));
        out.line(format!("return decodeFrom(allocator, &pb_r{});", pass));
        out.close("}");
        out.line("");
    }

    let mut body = Out::new("    ");
    body.push();
    body.push();
    Decoder::new(p, zero_copy).emit_steps(&mut body);
    out.open(format!("pub fn decodeFrom(allocator: std.mem.Allocator, pb_r: *PbReader{}) PbError!{} {{", decl, name));
    touch(out, &body.buf);
    // The errdefer below uses the allocator too.
    if !uses(&body.buf, "allocator") && !(allocates && uses(&body.buf, "p")) {
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
    out.open(format!("pub fn encode(self: *const {}, allocator: std.mem.Allocator{}) PbError![]u8 {{", name, decl));
    out.line("var pb_w = PbWriter.init(allocator);");
    out.line("errdefer pb_w.deinit();");
    out.line(format!("try self.encodeTo(&pb_w{});", pass));
    out.line("try pb_w.finish();");
    out.line("return pb_w.toOwnedSlice();");
    out.close("}");
    out.line("");
    if let Some((min, latest)) = versions {
        out.line(format!("/// Encode as protocol version `version` ({}..{}).", min, latest));
        out.open(format!(
            "pub fn encodeV(self: *const {}, allocator: std.mem.Allocator, version: u32{}) PbError![]u8 {{",
            name, decl
        ));
        out.line("var pb_w = PbWriter.init(allocator);");
        out.line("errdefer pb_w.deinit();");
        out.line(format!("try pb_w.setVersion(version, {}, {});", min, latest));
        out.line(format!("try self.encodeTo(&pb_w{});", pass));
        out.line("try pb_w.finish();");
        out.line("return pb_w.toOwnedSlice();");
        out.close("}");
        out.line("");
    }

    let encoder = Encoder::new(p);
    let mut body = Out::new("    ");
    body.push();
    body.push();
    encoder.emit_locals(&mut body);
    encoder.emit_steps(&mut body);
    out.open(format!("pub fn encodeTo(self: *const {}, pb_w: *PbWriter{}) PbError!void {{", name, decl));
    touch(out, &body.buf);
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
    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
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
