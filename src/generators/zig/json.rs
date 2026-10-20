//! `toJson`: every packet and union written as JSON to a writer. Integers
//! are numbers, bytes are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::ident;
use crate::generators::common::Out;
use crate::ir::{Member, Packet, Union, ValueType};

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { .. } => format!("try w.print(\"{{d}}\", .{{{}}});", v),
        ValueType::Float { .. } => format!("try w.print(\"{{d}}\", .{{@as(f64, {})}});", v),
        ValueType::Mac => format!("try pbJsonHex(w, &{});", v),
        ValueType::Str => format!("try std.json.stringify({}, .{{}}, w);", v),
        ValueType::Packet(_) | ValueType::Union(_) => format!("try {}.toJson(w);", v),
    }
}

fn member(out: &mut Out, m: &Member, place: &str) {
    match &m.array {
        None => out.line(elem(&m.ty, place)),
        Some(_) if m.ty.is_byte() => out.line(format!("try pbJsonHex(w, {});", place)),
        Some(_) => {
            out.line("try w.writeAll(\"[\");");
            out.open(format!("for ({}, 0..) |*x, i| {{", place));
            out.line("if (i > 0) try w.writeAll(\",\");");
            out.line(elem(&m.ty, "x.*"));
            out.close("}");
            out.line("try w.writeAll(\"]\");");
        }
    }
}

/// `pub fn toJson(self, w) !void` inside the packet's struct.
pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.line("/// Write the value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.open(format!("pub fn toJson(self: *const {}, w: anytype) anyerror!void {{", p.name));
    if p.members.is_empty() {
        out.line("_ = self;");
    }
    out.line("try w.writeAll(\"{\");");
    for (i, m) in p.members.iter().enumerate() {
        out.line(format!("try w.writeAll(\"{}\\\"{}\\\":\");", if i > 0 { "," } else { "" }, m.name));
        member(out, m, &format!("self.{}", ident(&m.name)));
    }
    out.line("try w.writeAll(\"}\");");
    out.close("}");
}

/// `pub fn toJson(self, w) !void` inside the union.
pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("");
    out.line("/// Write the value as JSON: {\"kind\": the arm's name, \"value\": its value or null}.");
    out.open(format!("pub fn toJson(self: *const {}, w: anytype) anyerror!void {{", u.name));
    out.open("switch (self.*) {");
    for arm in &u.arms {
        let (capture, value) = match (&arm.ty, arm.is_bytes()) {
            (None, _) => ("", "try w.writeAll(\"null\");".to_string()),
            (Some(_), true) => (" |x|", "try pbJsonHex(w, x);".to_string()),
            (Some(t), _) => (" |*x|", elem(t, "x.*")),
        };
        out.open(format!(".{} =>{} {{", ident(&arm.name), capture));
        out.line(format!("try w.writeAll(\"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\");", arm.name));
        out.line(value);
        out.line("try w.writeAll(\"}\");");
        out.close("},");
    }
    out.close("}");
    out.close("}");
}
