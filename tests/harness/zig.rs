use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::generators::zig_generator::ident;
use packet_builder::ir::{Member, Module, ValueType};
use packet_builder::Language;

use super::{member, packet, quote, run, set_literal, which, Case, Target};

pub struct ZigTarget;

fn zig() -> Option<PathBuf> {
    std::env::var_os("ZIG").map(PathBuf::from).or_else(|| which("zig"))
}

/// Zig fields use exact-width integers, so a value that does not fit is a
/// compile-time error rather than an encode error.
fn fits(ty: &ValueType, v: &serde_json::Value) -> bool {
    match ty {
        ValueType::Int { width, signed } => {
            let w = *width as u32;
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

fn dump_member(s: &mut String, m: &Member, place: &str) {
    let elem = |v: &str| match &m.ty {
        ValueType::Int { .. } => format!("try w.print(\"{{d}}\", .{{{}}});", v),
        ValueType::Float { .. } => format!("try w.print(\"{{d}}\", .{{@as(f64, {})}});", v),
        ValueType::Mac => format!("try hx(w, &{});", v),
        ValueType::Packet(n) => format!("try dump{}(w, &{});", n, v),
    };
    match &m.array {
        None => {
            let _ = writeln!(s, "    {}", elem(place));
        }
        Some(_) if m.ty.is_byte() => {
            let _ = writeln!(s, "    try hx(w, {});", place);
        }
        Some(_) => {
            let _ = writeln!(s, "    try w.writeAll(\"[\");");
            let _ = writeln!(s, "    for ({}, 0..) |x, i| {{", place);
            let _ = writeln!(s, "        if (i > 0) try w.writeAll(\",\");");
            let _ = writeln!(s, "        {}", elem("x"));
            let _ = writeln!(s, "    }}");
            let _ = writeln!(s, "    try w.writeAll(\"]\");");
        }
    }
}

impl Target for ZigTarget {
    fn language(&self) -> Language {
        Language::Zig
    }

    fn unavailable(&self) -> Option<String> {
        zig().is_none().then(|| "zig not found (set ZIG=/path/to/zig or put it on PATH)".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from("const std = @import(\"std\");\nconst pk = @import(\"packets.zig\");\n\n");
        s.push_str("fn hx(w: anytype, b: []const u8) !void {\n    try w.writeAll(\"\\\"\");\n    for (b) |c| try w.print(\"{x:0>2}\", .{c});\n    try w.writeAll(\"\\\"\");\n}\n\n");
        for p in &module.packets {
            let _ = writeln!(s, "fn dump{}(w: anytype, p: *const pk.{}) !void {{", p.name, p.name);
            s.push_str("    try w.writeAll(\"{\");\n");
            if p.members.is_empty() {
                s.push_str("    _ = p;\n");
            }
            for (i, m) in p.members.iter().enumerate() {
                let _ = writeln!(s, "    try w.writeAll(\"{}\\\"{}\\\":\");", if i > 0 { "," } else { "" }, m.name);
                dump_member(&mut s, m, &format!("p.{}", ident(&m.name)));
            }
            s.push_str("    try w.writeAll(\"}\");\n}\n\n");
        }
        // Zig only analyzes referenced functions; make sure all generated code compiles.
        s.push_str("comptime {\n");
        for p in &module.packets {
            for f in ["decode", "decodeFrom", "encode", "encodeTo", "deinit"] {
                let _ = writeln!(s, "    _ = &pk.{}.{};", p.name, f);
            }
        }
        s.push_str("}\n\n");
        s.push_str("pub fn main() !void {\n");
        s.push_str("    var gpa = std.heap.GeneralPurposeAllocator(.{}){};\n");
        s.push_str("    const allocator = gpa.allocator();\n");
        s.push_str("    const stdout = std.io.getStdOut().writer();\n");
        s.push_str("    var line = std.ArrayList(u8).init(allocator);\n");
        s.push_str("    var buf: [65536]u8 = undefined;\n");
        for c in cases {
            let p = packet(module, &c.packet);
            s.push_str("    {\n        line.clearRetainingCapacity();\n        const w = line.writer();\n");
            let _ = writeln!(s, "        const data = try std.fmt.hexToBytes(&buf, {});", quote(&c.hex));
            let _ = writeln!(s, "        if (pk.{}.decode(allocator, data)) |decoded| {{", p.name);
            s.push_str("            var p = decoded;\n            defer p.deinit(allocator);\n");
            let mut compile_time_reject = false;
            for (name, v) in &c.set {
                let m = member(p, name);
                if fits(&m.ty, v) {
                    let _ = writeln!(s, "            p.{} = {};", ident(&m.name), set_literal(v));
                } else {
                    compile_time_reject = true;
                }
            }
            if c.set.is_empty() {
                s.push_str("            _ = &p;\n");
            }
            s.push_str("            try w.writeAll(\"{\\\"ok\\\":true,\\\"value\\\":\");\n");
            let _ = writeln!(s, "            try dump{}(w, &p);", p.name);
            if compile_time_reject {
                s.push_str("            try w.writeAll(\",\\\"encode_error\\\":\\\"value does not fit the field type (rejected by the Zig compiler)\\\"}\");\n");
            } else {
                s.push_str("            if (p.encode(allocator)) |out| {\n                defer allocator.free(out);\n");
                s.push_str("                try w.writeAll(\",\\\"encoded\\\":\");\n                try hx(w, out);\n                try w.writeAll(\"}\");\n");
                s.push_str("            } else |err| {\n                try w.print(\",\\\"encode_error\\\":\\\"{s}\\\"}}\", .{@errorName(err)});\n            }\n");
            }
            s.push_str("        } else |err| {\n            try w.print(\"{{\\\"ok\\\":false,\\\"error\\\":\\\"{s}\\\"}}\", .{@errorName(err)});\n        }\n");
            s.push_str("        try stdout.print(\"{s}\\n\", .{line.items});\n    }\n");
        }
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
