use crate::models::parsing_models::{
    Endianness, ExprNode, PacketExpr, PacketExprList, TypeNode,
};
use crate::utilities::{CaseWrapper, Casing};
use std::fmt::Write as _;
pub struct CSharpGenerator {}

impl CSharpGenerator {
    pub fn generate(model: &PacketExprList) -> String {
        let mut out = String::new();
        out.push_str(&Self::create_headers());
        out.push_str(&Self::create_spacer());

        for pkt in &model.packets {
            out.push_str(&Self::build_class(pkt));
            out.push_str(&Self::create_spacer());
        }
        out
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        // We keep it minimal; consumers can add namespaces/partials as desired.
        // Uses BinaryPrimitives + BitConverter + Buffer.BlockCopy.
        "\
using System;
using System.Buffers.Binary;

"
        .to_string()
    }

    fn build_class(pkt: &PacketExpr) -> String {
        let class_name = CaseWrapper(pkt.name.clone()).to_pascal_case();

        // 1) properties
        let mut props = String::new();
        for f in &pkt.fields {
            let prop_ty = cs_field_type(&f.expr);
            let prop_name = CaseWrapper(f.id.clone()).to_pascal_case();
            let _ = writeln!(
                &mut props,
                "    public {} {} {{ get; set; }}",
                prop_ty, prop_name
            );
        }

        // 2) Serialize method
        let mut size_code = String::new();
        let mut ser_body = String::new();
        for f in &pkt.fields {
            let prop_name = CaseWrapper(f.id.clone()).to_pascal_case();
            let endian = f
                .endianness
                .as_ref()
                .or(pkt.endianness.as_ref())
                .unwrap_or(&Endianness::Le);
            size_code.push_str(&size_calc_snippet(&f.expr, &prop_name));
            ser_body.push_str(&serialize_snippet(&f.expr, &prop_name, endian.clone()));
        }

        // 3) Deserialize method
        let mut de_body = String::new();
        let n = pkt.fields.len();
        for (i, f) in pkt.fields.iter().enumerate() {
            let last = i + 1 == n;
            let prop_name = CaseWrapper(f.id.clone()).to_pascal_case();
            let endian = f.endianness.as_ref().or(pkt.endianness.as_ref()).unwrap_or(&Endianness::Le);
            de_body.push_str(&deserialize_snippet(&f.expr, &prop_name, endian.clone(), last));
        }

        format!(
            r#"public class {class_name}
{{
{props}
    public byte[] Serialize()
    {{
        // compute total size
        int total = 0;
{size_code}
        var data = new byte[total];
        int pos = 0;

{ser_body}
        return data;
    }}

    public static {class_name} Deserialize(byte[] data)
    {{
        var result = new {class_name}();
        int pos = 0;

{de_body}
        return result;
    }}
}}
"#,
            class_name = class_name,
            props = props,
            size_code = indent(&size_code, 2),
            ser_body = indent(&ser_body, 2),
            de_body = indent(&de_body, 2),
        )
    }
}

/* ============================================================
 * Mapping & helpers
 * ============================================================
*/

fn cs_field_type(t: &TypeNode) -> String {
    use TypeNode::*;
    let array_of = |base: &str, len: &Option<ExprNode>| {
        if len.is_some() {
            format!("{base}[]")
        } else {
            base.to_string()
        }
    };

    match t {
        // Integer/Float families
        UnsignedInteger8(len) => array_of("byte", len),
        Integer8(len) => array_of("sbyte", len),
        UnsignedInteger16(len) => array_of("ushort", len),
        Integer16(len) => array_of("short", len),
        UnsignedInteger32(len) => array_of("uint", len),
        Integer32(len) => array_of("int", len),
        UnsignedInteger64(len) => array_of("ulong", len),
        Integer64(len) => array_of("long", len),
        Float32(len) => array_of("float", len),
        Float64(len) => array_of("double", len),

        // DateTime: represent on-wire as 64-bit (epoch/ticks). Expose long(s).
        DateTime(len) => array_of("long", len),

        // Opaque byte blobs
        Bytes(_len) => "byte[]".to_string(),
        // Mac addresses as bytes (6 when const)
        MacAddress(_len) => "byte[]".to_string(),
    }
}

fn scalar_width_bytes(t: &TypeNode) -> usize {
    use TypeNode::*;
    match t {
        UnsignedInteger8(_) | Integer8(_) => 1,
        UnsignedInteger16(_) | Integer16(_) => 2,
        UnsignedInteger32(_) | Integer32(_) | Float32(_) => 4,
        UnsignedInteger64(_) | Integer64(_) | Float64(_) | DateTime(_) => 8,
        Bytes(_) | MacAddress(_) => 1, // element width; handled separately
    }
}

fn is_array_like(t: &TypeNode) -> bool {
    use TypeNode::*;
    match t {
        Bytes(_) | MacAddress(_) => true,
        UnsignedInteger8(len)
        | Integer8(len)
        | UnsignedInteger16(len)
        | Integer16(len)
        | UnsignedInteger32(len)
        | Integer32(len)
        | UnsignedInteger64(len)
        | Integer64(len)
        | Float32(len)
        | Float64(len)
        | DateTime(len) => len.is_some(),
    }
}

fn eval_len_const(expr: &ExprNode) -> Option<usize> {
    fn eval_i128(e: &ExprNode) -> Option<i128> {
        use ExprNode::*;
        match e {
            UnsignedInteger64Value(u) => Some(*u as i128),
            Integer64Value(i) => Some(*i as i128),
            Float64Value(f) => Some(*f as i128),
            ParenthesizedExpr(x) => eval_i128(x),
            Plus(a, b) => Some(eval_i128(a)? + eval_i128(b)?),
            Minus(a, b) => Some(eval_i128(a)? - eval_i128(b)?),
            Mult(a, b) => Some(eval_i128(a)? * eval_i128(b)?),
            Div(a, b) => {
                let d = eval_i128(b)?;
                if d == 0 {
                    None
                } else {
                    Some(eval_i128(a)? / d)
                }
            }
            Pow(a, b) => {
                let base = eval_i128(a)?;
                let exp = eval_i128(b)?;
                if exp < 0 {
                    return None;
                }
                let mut acc: i128 = 1;
                let mut e = exp as u128;
                let mut b = base;
                while e > 0 {
                    if e & 1 == 1 {
                        acc = acc.checked_mul(b)?;
                    }
                    e >>= 1;
                    if e > 0 {
                        b = b.checked_mul(b)?;
                    }
                }
                Some(acc)
            }
            _ => None,
        }
    }
    eval_i128(expr).and_then(|n| if n >= 0 { Some(n as usize) } else { None })
}

/* ============================================================
 * Codegen snippets
 * ============================================================
*/

fn size_calc_snippet(t: &TypeNode, name: &str) -> String {
    use TypeNode::*;
    let mut s = String::new();
    match t {
        Bytes(len_opt) => {
            if let Some(expr) = len_opt {
                if let Some(n) = eval_len_const(expr) {
                    let _ = writeln!(&mut s, "total += {n};");
                } else {
                    let _ = writeln!(&mut s, "total += {name}?.Length ?? 0;");
                }
            } else {
                let _ = writeln!(&mut s, "total += {name}?.Length ?? 0;");
            }
        }
        MacAddress(len_opt) => {
            if let Some(expr) = len_opt {
                if let Some(n) = eval_len_const(expr) {
                    let _ = writeln!(&mut s, "total += {n};");
                } else {
                    let _ = writeln!(&mut s, "total += {name}?.Length ?? 0;");
                }
            } else {
                let _ = writeln!(&mut s, "total += 6;");
            }
        }
        _ => {
            let w = scalar_width_bytes(t);
            if is_array_like(t) {
                let _ = writeln!(&mut s, "total += ({name}?.Length ?? 0) * {w};");
            } else {
                let _ = writeln!(&mut s, "total += {w};");
            }
        }
    }
    s
}

fn serialize_snippet(t: &TypeNode, name: &str, endian: Endianness) -> String {
    use Endianness::*;
    let mut s = String::new();
    match t {
        TypeNode::Bytes(_) | TypeNode::MacAddress(_) => {
            // Copy bytes as-is (mac default length is accounted in size)
            let _ = writeln!(
                &mut s,
                "if ({name} != null) {{ Buffer.BlockCopy({name}, 0, data, pos, {name}.Length); pos += {name}.Length; }}"
            );
        }
        _ => {
            let w = scalar_width_bytes(t);
            let write_scalar = |dst: &mut String, expr: String| {
                match (endian, w) {
                    (_, 1) => {
                        let _ = writeln!(dst, "data[pos++] = unchecked((byte)({expr}));");
                    }
                    (Le, 2) => {
                        let _ = writeln!(
                            dst,
                            "BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)({expr})); pos += 2;"
                        );
                    }
                    (Be, 2) => {
                        let _ = writeln!(
                            dst,
                            "BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(pos), (ushort)({expr})); pos += 2;"
                        );
                    }
                    (Le, 4) => match t {
                        TypeNode::Float32(_) => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(pos), BitConverter.SingleToInt32Bits((float)({expr}))); pos += 4;"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), (uint)({expr})); pos += 4;"
                            );
                        }
                    },
                    (Be, 4) => match t {
                        TypeNode::Float32(_) => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(pos), BitConverter.SingleToInt32Bits((float)({expr}))); pos += 4;"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(pos), (uint)({expr})); pos += 4;"
                            );
                        }
                    },
                    (Le, 8) => match t {
                        TypeNode::Float64(_) => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(pos), BitConverter.DoubleToInt64Bits((double)({expr}))); pos += 8;"
                            );
                        }
                        TypeNode::Integer64(_) | TypeNode::DateTime(_) => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(pos), (long)({expr})); pos += 8;"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(pos), (ulong)({expr})); pos += 8;"
                            );
                        }
                    },
                    (Be, 8) => match t {
                        TypeNode::Float64(_) => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteInt64BigEndian(data.AsSpan(pos), BitConverter.DoubleToInt64Bits((double)({expr}))); pos += 8;"
                            );
                        }
                        TypeNode::Integer64(_) | TypeNode::DateTime(_) => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteInt64BigEndian(data.AsSpan(pos), (long)({expr})); pos += 8;"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(pos), (ulong)({expr})); pos += 8;"
                            );
                        }
                    },
                    _ => { /* unreachable widths */ }
                }
            };

            if is_array_like(t) {
                let _ = writeln!(&mut s, "if ({name} != null) {{");
                let _ = writeln!(&mut s, "    for (int i = 0; i < {name}.Length; ++i) {{");
                write_scalar(&mut s, format!("{name}[i]"));
                let _ = writeln!(&mut s, "    }}");
                let _ = writeln!(&mut s, "}}");
            } else {
                write_scalar(&mut s, format!("{name}"));
            }
        }
    }
    s
}

fn deserialize_snippet(t: &TypeNode, name: &str, endian: Endianness, is_last: bool) -> String {
    use Endianness::*;
    let mut s = String::new();

    match t {
        TypeNode::Bytes(len_opt) => {
            if let Some(expr) = len_opt {
                if let Some(n) = eval_len_const(expr) {
                    let _ = writeln!(
                        &mut s,
                        "{name} = new byte[{n}]; Buffer.BlockCopy(data, pos, {name}, 0, {n}); pos += {n};"
                    );
                } else if is_last {
                    let _ = writeln!(
                        &mut s,
                        "{name} = new byte[data.Length - pos]; Buffer.BlockCopy(data, pos, {name}, 0, {name}.Length); pos = data.Length;"
                    );
                } else {
                    let _ = writeln!(
                        &mut s,
                        r#"throw new NotSupportedException("Dynamic-length bytes field not at end of buffer");"#
                    );
                }
            } else if is_last {
                let _ = writeln!(
                    &mut s,
                    "{name} = new byte[data.Length - pos]; Buffer.BlockCopy(data, pos, {name}, 0, {name}.Length); pos = data.Length;"
                );
            } else {
                let _ = writeln!(
                    &mut s,
                    r#"throw new NotSupportedException("Open-ended bytes field not at end of buffer");"#
                );
            }
        }
        TypeNode::MacAddress(len_opt) => {
            if let Some(expr) = len_opt {
                if let Some(n) = eval_len_const(expr) {
                    let _ = writeln!(
                        &mut s,
                        "{name} = new byte[{n}]; Buffer.BlockCopy(data, pos, {name}, 0, {n}); pos += {n};"
                    );
                } else if is_last {
                    let _ = writeln!(
                        &mut s,
                        "{name} = new byte[data.Length - pos]; Buffer.BlockCopy(data, pos, {name}, 0, {name}.Length); pos = data.Length;"
                    );
                } else {
                    let _ = writeln!(
                        &mut s,
                        r#"throw new NotSupportedException("Dynamic-length mac field not at end of buffer");"#
                    );
                }
            } else {
                let _ = writeln!(
                    &mut s,
                    "{name} = new byte[6]; Buffer.BlockCopy(data, pos, {name}, 0, 6); pos += 6;"
                );
            }
        }
        _ => {
            let w = scalar_width_bytes(t);

            let read_scalar = |dst: &mut String, lhs: String| {
                match (endian, w) {
                    (_, 1) => {
                        // byte/sbyte
                        let _ = writeln!(
                            dst,
                            "{lhs} = unchecked(({})(data[pos++]));",
                            match t {
                                TypeNode::Integer8(_) => "sbyte",
                                _ => "byte",
                            }
                        );
                    }
                    (Le, 2) => {
                        let _ = writeln!(
                            dst,
                            "{lhs} = ({} )BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(pos)); pos += 2;",
                            map_cs_scalar_for_width(t, 2)
                        );
                    }
                    (Be, 2) => {
                        let _ = writeln!(
                            dst,
                            "{lhs} = ({} )BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos)); pos += 2;",
                            map_cs_scalar_for_width(t, 2)
                        );
                    }
                    (Le, 4) => match t {
                        TypeNode::Float32(_) => {
                            let _ = writeln!(
                                dst,
                                "{{ var bits = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(pos)); pos += 4; {lhs} = BitConverter.Int32BitsToSingle(bits); }}"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "{lhs} = ({} )BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(pos)); pos += 4;",
                                map_cs_scalar_for_width(t, 4)
                            );
                        }
                    },
                    (Be, 4) => match t {
                        TypeNode::Float32(_) => {
                            let _ = writeln!(
                                dst,
                                "{{ var bits = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(pos)); pos += 4; {lhs} = BitConverter.Int32BitsToSingle(bits); }}"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "{lhs} = ({} )BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos)); pos += 4;",
                                map_cs_scalar_for_width(t, 4)
                            );
                        }
                    },
                    (Le, 8) => match t {
                        TypeNode::Float64(_) => {
                            let _ = writeln!(
                                dst,
                                "{{ var bits = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(pos)); pos += 8; {lhs} = BitConverter.Int64BitsToDouble(bits); }}"
                            );
                        }
                        TypeNode::Integer64(_) | TypeNode::DateTime(_) => {
                            let _ = writeln!(
                                dst,
                                "{lhs} = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(pos)); pos += 8;"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "{lhs} = ({} )BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(pos)); pos += 8;",
                                map_cs_scalar_for_width(t, 8)
                            );
                        }
                    },
                    (Be, 8) => match t {
                        TypeNode::Float64(_) => {
                            let _ = writeln!(
                                dst,
                                "{{ var bits = BinaryPrimitives.ReadInt64BigEndian(data.AsSpan(pos)); pos += 8; {lhs} = BitConverter.Int64BitsToDouble(bits); }}"
                            );
                        }
                        TypeNode::Integer64(_) | TypeNode::DateTime(_) => {
                            let _ = writeln!(
                                dst,
                                "{lhs} = BinaryPrimitives.ReadInt64BigEndian(data.AsSpan(pos)); pos += 8;"
                            );
                        }
                        _ => {
                            let _ = writeln!(
                                dst,
                                "{lhs} = ({} )BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(pos)); pos += 8;",
                                map_cs_scalar_for_width(t, 8)
                            );
                        }
                    },
                    _ => {}
                }
            };

            if is_array_like(t) {
                // Constant-length array? allocate exact; otherwise if last, use remaining bytes / elem size
                if let Some(len_expr) = type_len_expr(t) {
                    if let Some(n) = eval_len_const(len_expr) {
                        let ty = cs_field_type(t).trim_end_matches("[]").to_string();
                        let _ = writeln!(&mut s, "{name} = new {ty}[{n}];");
                        let _ = writeln!(&mut s, "for (int i = 0; i < {n}; ++i) {{");
                        read_scalar(&mut s, format!("{name}[i]"));
                        let _ = writeln!(&mut s, "}}");
                    } else if is_last {
                        let ty = cs_field_type(t).trim_end_matches("[]").to_string();
                        let elem = w;
                        let _ = writeln!(
                            &mut s,
                            "{{ int rem = data.Length - pos; int cnt = rem / {elem}; {name} = new {ty}[cnt]; for (int i = 0; i < cnt; ++i) {{"
                        );
                        read_scalar(&mut s, format!("{name}[i]"));
                        let _ = writeln!(&mut s, "}} }}");
                    } else {
                        let _ = writeln!(
                            &mut s,
                            r#"throw new NotSupportedException("Dynamic-length non-byte array not at end of buffer");"#
                        );
                    }
                } else {
                    // Fallback (shouldn't happen): treat as scalar
                    read_scalar(&mut s, name.to_string());
                }
            } else {
                read_scalar(&mut s, format!("{name}"));
            }
        }
    }

    s
}

fn map_cs_scalar_for_width(t: &TypeNode, w: usize) -> &'static str {
    use TypeNode::*;
    match (t, w) {
        (Integer16(_), 2) => "short",
        (UnsignedInteger16(_), 2) => "ushort",
        (Integer32(_), 4) => "int",
        (UnsignedInteger32(_), 4) => "uint",
        (Integer64(_), 8) | (DateTime(_), 8) => "long",
        (UnsignedInteger64(_), 8) => "ulong",
        // Fallback to unsigned width for other combos (we cast on store/read as needed)
        _ => match w {
            2 => "ushort",
            4 => "uint",
            8 => "ulong",
            _ => "byte",
        },
    }
}

fn type_len_expr<'a>(t: &'a TypeNode) -> Option<&'a ExprNode> {
    use TypeNode::*;
    match t {
        UnsignedInteger8(e) | Integer8(e) | UnsignedInteger16(e) | Integer16(e)
        | UnsignedInteger32(e) | Integer32(e) | UnsignedInteger64(e) | Integer64(e)
        | Float32(e) | Float64(e) | DateTime(e) => e.as_ref(),
        Bytes(e) | MacAddress(e) => e.as_ref(), // used for const detection
    }
}

fn indent(s: &str, tabs: usize) -> String {
    let pad = "    ".repeat(tabs);
    s.lines()
        .map(|l| {
            if l.is_empty() {
                "\n".to_string()
            } else {
                format!("{pad}{l}\n")
            }
        })
        .collect()
}
