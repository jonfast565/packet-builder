use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::zig::ident;
use packet_builder::ir::{Module, ValueType};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct ZigTarget;

fn zig() -> Option<PathBuf> {
    std::env::var_os("ZIG").map(PathBuf::from).or_else(|| which("zig"))
}

/// Zig fields use exact-width integers, so a value that does not fit is a
/// compile-time error rather than an encode error.
fn fits(ty: &ValueType, v: &serde_json::Value) -> bool {
    match ty {
        ValueType::Int { width, signed } => {
            let w = *width;
            if *signed {
                let v = v.as_i64().unwrap_or(i64::MAX);
                w >= 64 || (v >= -(1i64 << (w - 1)) && v < (1i64 << (w - 1)))
            } else {
                match v.as_u64() {
                    Some(v) => w >= 64 || v < (1u64 << w),
                    None => false,
                }
            }
        }
        _ => true,
    }
}

impl Target for ZigTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Zig)
    }

    fn unavailable(&self) -> Option<String> {
        zig().is_none().then(|| "zig not found (set ZIG=/path/to/zig or put it on PATH)".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("const std = @import(\"std\");\nconst pk = @import(\"packets.zig\");\n\n");
        s.push_str("fn hx(w: anytype, b: []const u8) !void {\n    try w.writeAll(\"\\\"\");\n    for (b) |c| try w.print(\"{x:0>2}\", .{c});\n    try w.writeAll(\"\\\"\");\n}\n\n");
        // Zig only analyzes referenced functions; make sure all generated code compiles.
        s.push_str("comptime {\n");
        for p in &module.packets {
            for f in ["decode", "decodeFrom", "encode", "encodeTo", "deinit", "toJson"] {
                let _ = writeln!(s, "    _ = &pk.{}.{};", p.name, f);
            }
            if p.params.is_empty() {
                let _ = writeln!(s, "    _ = &pk.{}.tryDecode;", p.name);
            }
            if super::has_frame(module, p) {
                let _ = writeln!(s, "    _ = &pk.{}.frameLen;", p.name);
            }
        }
        s.push_str("}\n\n");
        s.push_str("const Writer = std.ArrayList(u8).Writer;\n\n");
        s.push_str("fn encodeAll(p: anytype, pw: *pk.PbWriter) pk.PbError!void {\n    try p.encodeTo(pw);\n    try pw.finish();\n}\n\n");
        s.push_str(
            r#"fn pbErr(w: Writer, pre: []const u8, err: anyerror, trace: *const pk.PbTrace) !void {
    const kind = switch (err) {
        error.Incomplete => "incomplete",
        error.Invalid => "invalid",
        error.Range => "range",
        error.InvalidText => "text",
        error.Mismatch => "mismatch",
        error.Constraint => "constraint",
        else => "other",
    };
    try w.print(",\"{s}error\":\"{s}\",\"{s}kind\":\"{s}\",\"{s}path\":\"", .{ pre, @errorName(err), pre, kind, pre });
    try trace.writePath(w);
    try w.writeAll("\"");
}

"#,
        );
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let _ = writeln!(s, "fn case{}(allocator: std.mem.Allocator, w: Writer) anyerror!void {{", i);
            s.push_str("    var buf: [4096]u8 = undefined;\n");
            let _ = writeln!(s, "    const data = try std.fmt.hexToBytes(&buf, {});", quote(&c.hex));
            s.push_str("    var r = pk.PbReader.init(data);\n");
            let _ = writeln!(s, "    if (pk.{}.decodeFrom(allocator, &r)) |decoded| {{", p.name);
            s.push_str("        var p = decoded;\n        defer p.deinit(allocator);\n");
            let mut compile_time_reject = false;
            for (name, v) in &c.set {
                let m = super::resolve_path(module, p, name).last().unwrap().1;
                if fits(&m.ty, v) {
                    let path = super::accessor(module, p, name, |_, m| ident(&m.name));
                    if v.is_string() {
                        let _ = writeln!(s, "        allocator.free(p.{});", path);
                        let _ = writeln!(s, "        p.{} = try allocator.dupe(u8, {});", path, set_literal(v));
                    } else {
                        let _ = writeln!(s, "        p.{} = {};", path, set_literal(v));
                    }
                } else {
                    compile_time_reject = true;
                }
            }
            if c.set.is_empty() {
                s.push_str("        _ = &p;\n");
            }
            s.push_str("        try w.writeAll(\"{\\\"ok\\\":true,\\\"value\\\":\");\n");
            s.push_str("        try p.toJson(w);\n");
            if compile_time_reject {
                s.push_str("        try w.writeAll(\",\\\"encode_error\\\":\\\"value does not fit the field type (rejected by the Zig compiler)\\\",\\\"encode_kind\\\":\\\"range\\\"}\");\n");
            } else {
                s.push_str("        var pw = pk.PbWriter.init(allocator);\n        defer pw.deinit();\n");
                s.push_str("        if (encodeAll(&p, &pw)) |_| {\n");
                s.push_str("            try w.writeAll(\",\\\"encoded\\\":\");\n            try hx(w, pw.buf.items);\n            try w.writeAll(\"}\");\n");
                s.push_str("        } else |err| {\n            try pbErr(w, \"encode_\", err, &pw.trace);\n            try w.writeAll(\"}\");\n        }\n");
            }
            s.push_str("    } else |err| {\n        try w.writeAll(\"{\\\"ok\\\":false\");\n        try pbErr(w, \"\", err, &r.trace);\n        try w.writeAll(\"}\");\n    }\n");
            s.push_str("    try w.writeAll(\"\\n\");\n");
            let _ = writeln!(s, "    if (pk.{}.tryDecode(allocator, data)) |st| switch (st) {{", p.name);
            s.push_str("        .done => |d| {\n            var v = d.value;\n            v.deinit(allocator);\n            try w.print(\"{{\\\"try\\\":\\\"done\\\",\\\"n\\\":{d}\", .{d.consumed});\n        },\n");
            s.push_str(
                "        .incomplete => |n| try w.print(\"{{\\\"try\\\":\\\"incomplete\\\",\\\"n\\\":{d}\", .{n}),\n",
            );
            s.push_str("    } else |_| try w.writeAll(\"{\\\"try\\\":\\\"error\\\"\");\n");
            if super::has_frame(module, p) {
                let _ = writeln!(s, "    if (pk.{}.frameLen(data)) |f| {{", p.name);
                s.push_str("        if (f) |n| try w.print(\",\\\"frame\\\":{d}\", .{n}) else try w.writeAll(\",\\\"frame\\\":null\");\n");
                s.push_str("    } else |_| try w.writeAll(\",\\\"frame\\\":\\\"error\\\"\");\n");
            }
            s.push_str("    try w.writeAll(\"}\");\n}\n\n");
        }
        s.push_str("pub fn main() !void {\n");
        s.push_str("    var gpa = std.heap.GeneralPurposeAllocator(.{}){};\n");
        s.push_str("    const allocator = gpa.allocator();\n");
        s.push_str("    const stdout = std.io.getStdOut().writer();\n");
        s.push_str("    var line = std.ArrayList(u8).init(allocator);\n");
        s.push_str("    const cases = [_]*const fn (std.mem.Allocator, Writer) anyerror!void{\n");
        for i in 0..cases.len() {
            let _ = writeln!(s, "        case{},", i);
        }
        s.push_str("    };\n");
        s.push_str("    for (cases) |case| {\n        line.clearRetainingCapacity();\n        try case(allocator, line.writer());\n        try stdout.print(\"{s}\\n\", .{line.items});\n    }\n");
        s.push_str("    line.deinit();\n");
        s.push_str("    if (gpa.deinit() == .leak) return error.MemoryLeak;\n}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.zig"), generated).unwrap();
        fs::write(dir.join("main.zig"), harness).unwrap();
        let zig = zig().unwrap();
        run(
            Command::new(&zig)
                .current_dir(dir)
                .args(["build-exe", "main.zig", "-femit-bin=harness"])
                .env("ZIG_GLOBAL_CACHE_DIR", dir.join(".zig-cache-global"))
                .env("ZIG_LOCAL_CACHE_DIR", dir.join(".zig-cache")),
            "zig build-exe",
        )?;
        run(&mut Command::new(dir.join("harness")), "zig harness")
    }
}
