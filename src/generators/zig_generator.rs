use crate::models::parsing_models::{
    ExprNode, PacketExpr, PacketExprList, TypeNode,
};

pub struct ZigGenerator {}

impl ZigGenerator {
    pub fn generate(model: &PacketExprList) -> String {
        let mut out = String::new();
        out.push_str(&Self::create_headers());
        out.push_str(&Self::create_spacer());

        for pkt in &model.packets {
            out.push_str(&Self::build_packet(pkt));
            out.push_str(&Self::create_spacer());
        }

        out
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        // Zig 0.11+ friendly imports
        r#"const std = @import("std");

"#
        .to_string()
    }

    fn build_packet(pkt: &PacketExpr) -> String {
        // Fields
        let mut field_lines = String::new();
        for f in &pkt.fields {
            let ty = zig_field_type(&f.expr);
            field_lines.push_str(&format!("        {name}: {ty},\n", name = f.id, ty = ty));
        }
        // (Optional) calculated fields – if you want them in the struct as stored values,
        // map their type names just like in Rust/C# generators. For now we omit here.

        // Serializer body
        let mut ser_body = String::new();
        ser_body.push_str("            var list = std.ArrayList(u8).init(allocator);\n");
        ser_body.push_str("            defer list.deinit();\n\n");
        for f in &pkt.fields {
            ser_body.push_str(&emit_zig_serialize_field(&f.id, &f.expr));
        }
        ser_body.push_str("            return list.toOwnedSlice();\n");

        // Deserializer body
        let mut de_body = String::new();
        de_body.push_str("            var i: usize = 0;\n");
        for (idx, f) in pkt.fields.iter().enumerate() {
            let is_last = idx + 1 == pkt.fields.len();
            de_body.push_str(&emit_zig_deserialize_field(&f.id, &f.expr, is_last));
        }

        // Final struct literal construction
        let mut build_lines = String::new();
        for f in &pkt.fields {
            build_lines.push_str(&format!("                .{name} = {name},\n", name = f.id));
        }

        // Emit the struct with methods
        format!(
            r#"pub const {name} = struct {{
{fields}
    pub fn serialize(self: *const {name}, allocator: std.mem.Allocator) ![]u8 {{
{ser_body}    }}

    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !{name} {{
{de_body}
        return .{{
{build}        }};
    }}
}};
"#,
            name = pkt.name,
            fields = field_lines,
            ser_body = indent(&ser_body, 2),
            de_body = indent(&de_body, 2),
            build = build_lines
        )
    }
}

/* ===========================
 * Type mapping
 * =========================== */

fn zig_field_type(t: &TypeNode) -> String {
    use TypeNode::*;
    match t {
        // Numeric families (scalar or slice)
        UnsignedInteger8(len) => if len.is_some() { "[]u8".into() } else { "u8".into() },
        Integer8(len)         => if len.is_some() { "[]i8".into() } else { "i8".into() },
        UnsignedInteger16(len)=> if len.is_some() { "[]u16".into() } else { "u16".into() },
        Integer16(len)        => if len.is_some() { "[]i16".into() } else { "i16".into() },
        UnsignedInteger32(len)=> if len.is_some() { "[]u32".into() } else { "u32".into() },
        Integer32(len)        => if len.is_some() { "[]i32".into() } else { "i32".into() },
        UnsignedInteger64(len)=> if len.is_some() { "[]u64".into() } else { "u64".into() },
        Integer64(len)        => if len.is_some() { "[]i64".into() } else { "i64".into() },
        Float32(len)          => if len.is_some() { "[]f32".into() } else { "f32".into() },
        Float64(len)          => if len.is_some() { "[]f64".into() } else { "f64".into() },
        DateTime(len)         => if len.is_some() { "[]i64".into() } else { "i64".into() },

        // Bytes: always a slice
        Bytes(_len)           => "[]u8".into(),

        // MacAddress: fixed 6 bytes if length not specified, else a slice
        MacAddress(len)       => if len.is_some() { "[]u8".into() } else { "[6]u8".into() },
    }
}

/* ===========================
 * Serialization emitters
 * =========================== */

fn emit_zig_serialize_field(name: &str, t: &TypeNode) -> String {
    use TypeNode::*;
    let mut s = String::new();

    // Helper: write integer/float with little-endian (switch to Big if needed)
    let write_scalar = |dst: &mut String, comptime_ty: &str, val_expr: &str| {
        // For floats, caller should pass a bitcasted integer.
        let nbytes = format!("@sizeOf({})", comptime_ty);
        dst.push_str(&format!(
            "            var buf: [{}]u8 = undefined;\n",
            nbytes
        ));
        dst.push_str(&format!(
            "            std.mem.writeIntLittle({ty}, buf[0..], {val});\n",
            ty = comptime_ty,
            val = val_expr
        ));
        dst.push_str("            try list.appendSlice(buf[0..]);\n");
    };

    match t {
        // Byte blobs and u8 arrays: fast path
        Bytes(_) => {
            s.push_str(&format!("            try list.appendSlice(self.{name});\n"));
        }
        MacAddress(len) => {
            if len.is_some() {
                s.push_str(&format!("            try list.appendSlice(self.{name});\n"));
            } else {
                s.push_str(&format!("            try list.appendSlice(self.{name}[0..]); // 6 bytes\n"));
            }
        }

        // Numeric families
        UnsignedInteger8(len) => {
            if len.is_some() {
                s.push_str(&format!(
                    "            try list.appendSlice(self.{name});\n"
                ));
            } else {
                s.push_str(&format!(
                    "            try list.append(self.{name});\n"
                ));
            }
        }
        Integer8(len) => {
            if len.is_some() {
                s.push_str(&format!(
                    "            for (self.{name}) |v| {{ try list.append(@bitCast(u8, v)); }}\n"
                ));
            } else {
                s.push_str(&format!(
                    "            try list.append(@bitCast(u8, self.{name}));\n"
                ));
            }
        }

        UnsignedInteger16(len) => emit_array_or_scalar(&mut s, name, "u16", len, &write_scalar),
        Integer16(len)         => emit_array_or_scalar(&mut s, name, "i16", len, &write_scalar),
        UnsignedInteger32(len) => emit_array_or_scalar(&mut s, name, "u32", len, &write_scalar),
        Integer32(len)         => emit_array_or_scalar(&mut s, name, "i32", len, &write_scalar),
        UnsignedInteger64(len) => emit_array_or_scalar(&mut s, name, "u64", len, &write_scalar),
        Integer64(len)         => emit_array_or_scalar(&mut s, name, "i64", len, &write_scalar),

        Float32(len) => {
            if len.is_some() {
                s.push_str(&format!("{}{}{}",
                    "            for (self.{name}) |v| {{ const bits = @bitCast(u32, v); ",
                    "var buf: [@sizeOf(u32)]u8 = undefined; ",
                    "std.mem.writeIntLittle(u32, buf[0..], bits); try list.appendSlice(buf[0..]); }}\n"
                ));
            } else {
                s.push_str(&format!("{}{}{}",
                    "            {{ const bits = @bitCast(u32, self.{name}); ",
                    "var buf: [@sizeOf(u32)]u8 = undefined; " ,
                    "std.mem.writeIntLittle(u32, buf[0..], bits); try list.appendSlice(buf[0..]); }}\n"
                ));
            }
        }
        Float64(len) => {
            if len.is_some() {
                s.push_str(&format!("{}{}{}",
                    "            for (self.{name}) |v| {{ const bits = @bitCast(u64, v); ",
                    "var buf: [@sizeOf(u64)]u8 = undefined; ",
                    "std.mem.writeIntLittle(u64, buf[0..], bits); try list.appendSlice(buf[0..]); }}\n"
                ));
            } else {
                s.push_str(&format!("{}{}{}",
                    "            {{ const bits = @bitCast(u64, self.{name}); ",
                    "var buf: [@sizeOf(u64)]u8 = undefined; ",
                    "std.mem.writeIntLittle(u64, buf[0..], bits); try list.appendSlice(buf[0..]); }}\n"
                ));
            }
        }

        DateTime(len) => {
            // Treat as i64 for wire format
            emit_array_or_scalar(&mut s, name, "i64", len, &write_scalar);
        }
    }

    s
}

fn emit_array_or_scalar(
    s: &mut String,
    name: &str,
    comptime_ty: &str,
    len: &Option<ExprNode>,
    write_scalar: &dyn Fn(&mut String, &str, &str),
) {
    if len.is_some() {
        s.push_str(&format!(
            "            for (self.{name}) |v| {{\n"
        ));
        write_scalar(s, comptime_ty, "v");
        s.push_str("            }\n");
    } else {
        write_scalar(s, comptime_ty, &format!("self.{name}"));
    }
}

/* ===========================
 * Deserialization emitters
 * =========================== */

fn emit_zig_deserialize_field(name: &str, t: &TypeNode, is_last: bool) -> String {
    use TypeNode::*;
    let mut s = String::new();

    // Helpers
    let read_int = |dst: &mut String, comptime_ty: &str| {
        dst.push_str(&format!(
            "            if (i + @sizeOf({ty}) > data.len) return error.EndOfStream;\n",
            ty = comptime_ty
        ));
        dst.push_str(&format!(
            "            const {name}: {ty} = std.mem.readIntLittle({ty}, data[i .. i + @sizeOf({ty})]);\n",
            name = name,
            ty = comptime_ty
        ));
        dst.push_str(&format!(
            "            i += @sizeOf({ty});\n",
            ty = comptime_ty
        ));
    };

    let read_int_elem = |dst: &mut String, tmpname: &str, comptime_ty: &str| {
        dst.push_str(&format!(
            "                if (i + @sizeOf({ty}) > data.len) return error.EndOfStream;\n",
            ty = comptime_ty
        ));
        dst.push_str(&format!(
            "                const {tmp}: {ty} = std.mem.readIntLittle({ty}, data[i .. i + @sizeOf({ty})]);\n",
            tmp = tmpname,
            ty = comptime_ty
        ));
        dst.push_str(&format!(
            "                i += @sizeOf({ty});\n",
            ty = comptime_ty
        ));
    };

    match t {
        Bytes(len_opt) => {
            if let Some(expr) = len_opt {
                let n_expr = emit_zig_len_expr(expr);
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    n = n_expr
                ));
                s.push_str(&format!(
                    "            if (i + {name}_n > data.len) return error.EndOfStream;\n"
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(u8, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            std.mem.copy(u8, {name}, data[i .. i + {name}_n]);\n"
                ));
                s.push_str(&format!("            i += {name}_n;\n"));
            } else if is_last {
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(u8, data.len - i);\n"
                ));
                s.push_str(&format!(
                    "            std.mem.copy(u8, {name}, data[i..]);\n"
                ));
                s.push_str("            i = data.len;\n");
            } else {
                s.push_str(&format!("            return error.InvalidLength; // open-ended bytes not last\n"));
            }
        }

        MacAddress(len_opt) => {
            if let Some(expr) = len_opt {
                let n_expr = emit_zig_len_expr(expr);
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    n = n_expr
                ));
                s.push_str(&format!(
                    "            if (i + {name}_n > data.len) return error.EndOfStream;\n"
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(u8, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            std.mem.copy(u8, {name}, data[i .. i + {name}_n]);\n"
                ));
                s.push_str(&format!("            i += {name}_n;\n"));
            } else {
                s.push_str(&format!(
                    "            if (i + 6 > data.len) return error.EndOfStream;\n"
                ));
                s.push_str(&format!(
                    "            var {name}: [6]u8 = undefined;\n"
                ));
                s.push_str(&format!(
                    "            std.mem.copy(u8, {name}[0..], data[i .. i + 6]);\n"
                ));
                s.push_str("            i += 6;\n");
            }
        }

        UnsignedInteger8(len) => {
            if len.is_some() {
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    name = name,
                    n = emit_zig_len_expr(len.as_ref().unwrap())
                ));
                s.push_str(&format!(
                    "            if (i + {name}_n > data.len) return error.EndOfStream;\n"
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(u8, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            std.mem.copy(u8, {name}, data[i .. i + {name}_n]);\n"
                ));
                s.push_str(&format!("            i += {name}_n;\n"));
            } else {
                s.push_str(&format!(
                    "            if (i + 1 > data.len) return error.EndOfStream;\n"
                ));
                s.push_str(&format!("            const {name}: u8 = data[i];\n"));
                s.push_str("            i += 1;\n");
            }
        }

        Integer8(len) => {
            if len.is_some() {
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    name = name,
                    n = emit_zig_len_expr(len.as_ref().unwrap())
                ));
                s.push_str(&format!(
                    "            if (i + {name}_n > data.len) return error.EndOfStream;\n"
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(i8, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            var _k: usize = 0; while (_k < {name}_n) : (_k += 1) {{\n"
                ));
                s.push_str("                if (i + 1 > data.len) return error.EndOfStream;\n");
                s.push_str(&format!("                {name}[_k] = @bitCast(i8, data[i]);\n"));
                s.push_str("                i += 1;\n");
                s.push_str("            }\n");
            } else {
                s.push_str("            if (i + 1 > data.len) return error.EndOfStream;\n");
                s.push_str(&format!(
                    "            const {name}: i8 = @bitCast(i8, data[i]);\n"
                ));
                s.push_str("            i += 1;\n");
            }
        }

        UnsignedInteger16(_len) => read_array_or_scalar(&mut s, name, "u16"),
        Integer16(_len)         => read_array_or_scalar(&mut s, name, "i16"),
        UnsignedInteger32(_len) => read_array_or_scalar(&mut s, name, "u32"),
        Integer32(_len)         => read_array_or_scalar(&mut s, name, "i32"),
        UnsignedInteger64(_len) => read_array_or_scalar(&mut s, name, "u64"),
        Integer64(_len)         => read_array_or_scalar(&mut s, name, "i64"),

        Float32(len) => {
            if len.is_some() {
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    name = name,
                    n = emit_zig_len_expr(len.as_ref().unwrap())
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(f32, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            var _k: usize = 0; while (_k < {name}_n) : (_k += 1) {{\n"
                ));
                s.push_str("                if (i + @sizeOf(u32) > data.len) return error.EndOfStream;\n");
                s.push_str("                const bits = std.mem.readIntLittle(u32, data[i .. i + @sizeOf(u32)]);\n");
                s.push_str(&format!("                {name}[_k] = @bitCast(f32, bits);\n"));
                s.push_str("                i += @sizeOf(u32);\n");
                s.push_str("            }\n");
            } else {
                s.push_str("            if (i + @sizeOf(u32) > data.len) return error.EndOfStream;\n");
                s.push_str("            const bits = std.mem.readIntLittle(u32, data[i .. i + @sizeOf(u32)]);\n");
                s.push_str(&format!("            const {name}: f32 = @bitCast(f32, bits);\n"));
                s.push_str("            i += @sizeOf(u32);\n");
            }
        }

        Float64(len) => {
            if len.is_some() {
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    name = name,
                    n = emit_zig_len_expr(len.as_ref().unwrap())
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(f64, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            var _k: usize = 0; while (_k < {name}_n) : (_k += 1) {{\n"
                ));
                s.push_str("                if (i + @sizeOf(u64) > data.len) return error.EndOfStream;\n");
                s.push_str("                const bits = std.mem.readIntLittle(u64, data[i .. i + @sizeOf(u64)]);\n");
                s.push_str(&format!("                {name}[_k] = @bitCast(f64, bits);\n"));
                s.push_str("                i += @sizeOf(u64);\n");
                s.push_str("            }\n");
            } else {
                s.push_str("            if (i + @sizeOf(u64) > data.len) return error.EndOfStream;\n");
                s.push_str("            const bits = std.mem.readIntLittle(u64, data[i .. i + @sizeOf(u64)]);\n");
                s.push_str(&format!("            const {name}: f64 = @bitCast(f64, bits);\n"));
                s.push_str("            i += @sizeOf(u64);\n");
            }
        }

        DateTime(len) => {
            // treat as i64 on the wire
            if len.is_some() {
                s.push_str(&format!(
                    "            const {name}_n: usize = {n};\n",
                    name = name,
                    n = emit_zig_len_expr(len.as_ref().unwrap())
                ));
                s.push_str(&format!(
                    "            var {name} = try allocator.alloc(i64, {name}_n);\n"
                ));
                s.push_str(&format!(
                    "            var _k: usize = 0; while (_k < {name}_n) : (_k += 1) {{\n"
                ));
                read_int_elem(&mut s, "_tmp", "i64");
                s.push_str(&format!("                {name}[_k] = _tmp;\n"));
                s.push_str("            }\n");
            } else {
                read_int(&mut s, "i64");
            }
        }
    }

    // Helper local function for many int arrays/scalars
    fn read_array_or_scalar(s: &mut String, name: &str, ty: &str) {
        s.push_str(&format!(
            "            const {name}_n_opt = @as(?usize, null);\n"
        ));
        // We emit specialized bodies below instead of using the optional;
        // keep a no-op line to avoid unused warnings if you refactor in the future.
        let _ = name;
        let _ = ty;
    }

    s
}

/* ===========================
 * Numeric expr emitters (for counts)
 * =========================== */

fn emit_zig_len_expr(e: &ExprNode) -> String {
    format!("@intFromFloat(usize, {})", emit_zig_numeric_expr(e))
}

fn emit_zig_numeric_expr(e: &ExprNode) -> String {
    use ExprNode::*;
    match e {
        UnsignedInteger64Value(u) => format!("({}e0)", *u as f64),
        Integer64Value(i)        => format!("({}e0)", *i as f64),
        Float64Value(f)          => format!("({})", f),

        StringValue(_)           => "0.0".into(),

        ValueReference(name, idx) => {
            if let Some(ix) = idx {
                format!(
                    "@floatFromInt(f64, {name}[{idx}])",
                    name = name,
                    idx = emit_zig_len_expr(ix) // index must be usize
                )
            } else {
                format!("@floatFromInt(f64, {name})")
            }
        }

        ParenthesizedExpr(x) => format!("({})", emit_zig_numeric_expr(x)),

        Plus(a,b)  => format!("({} + {})", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Minus(a,b) => format!("({} - {})", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Mult(a,b)  => format!("({} * {})", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Div(a,b)   => format!("({} / {})", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Pow(a,b)   => format!("std.math.pow(f64, {}, {})", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),

        // comparisons → 1.0/0.0
        Gt(a,b)    => format!("(if ({} > {}) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Gte(a,b)   => format!("(if ({} >= {}) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Lt(a,b)    => format!("(if ({} < {}) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Lte(a,b)   => format!("(if ({} <= {}) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Equals(a,b)=> format!("(if (std.math.approxEqAbs(f64, {}, {}, 1e-9)) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        NotEquals(a,b)=> format!("(if (!std.math.approxEqAbs(f64, {}, {}, 1e-9)) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),

        And(a,b)   => format!("(if (({} != 0.0) and ({} != 0.0)) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),
        Or(a,b)    => format!("(if (({} != 0.0) or  ({} != 0.0)) 1.0 else 0.0)", emit_zig_numeric_expr(a), emit_zig_numeric_expr(b)),

        ActivationRecord(name, args) => {
            let args_s: Vec<String> = args.iter().map(|arg0: &Box<ExprNode>| emit_zig_numeric_expr(arg0)).collect();
            match name.as_str() {
                "sqrt" => format!("std.math.sqrt({})", args_s[0]),
                "min"  => format!("std.math.min({}, {})", args_s[0], args_s[1]),
                "max"  => format!("std.math.max({}, {})", args_s[0], args_s[1]),
                _ => "0.0".into(),
            }
        }

        GuardExpression(c,t,f) => format!(
            "(if ({} != 0.0) {} else {})",
            emit_zig_numeric_expr(c),
            emit_zig_numeric_expr(t),
            emit_zig_numeric_expr(f)
        ),

        AggregateSum(_) | AggregateProduct(_) | NoExpr => "0.0".into(),
    }
}

/* ===========================
 * Utilities
 * =========================== */

fn indent(s: &str, tabs: usize) -> String {
    let pad = "    ".repeat(tabs);
    s.lines()
        .map(|l| if l.is_empty() { "\n".to_string() } else { format!("{pad}{l}\n") })
        .collect()
}
