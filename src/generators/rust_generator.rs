use crate::models::parsing_models::{
    Endianness, ExprNode, PacketExpr, PacketExprList, TypeNode,
};
use std::fmt::Write as _;
pub struct RustGenerator {}

impl RustGenerator {
    pub fn generate(model: &PacketExprList) -> String {
        let mut out = String::new();
        out.push_str(&Self::create_headers());
        out.push_str(&Self::create_spacer());

        for pkt in &model.packets {
            out.push_str(&Self::build_struct(pkt));
            out.push_str(&Self::create_serialization_impl(pkt));
            out.push_str(&Self::create_spacer());
        }

        out
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        r#"use std::io::{Cursor, Read, Write};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Serialize, Deserialize};

"#
        .to_string()
    }

    /* =========================
     * Struct + impl emission
     * ========================= */

    fn build_struct(pkt: &PacketExpr) -> String {
        let mut fields = String::new();

        for f in &pkt.fields {
            let ty = rust_field_type(&f.expr);
            let _ = writeln!(&mut fields, "    pub {}: {},", f.id, ty);
        }

        for cf in &pkt.calculated_fields {
            let ty = rust_type_from_type_name(&cf.data_type);
            let _ = writeln!(&mut fields, "    pub {}: {},", cf.name, ty);
        }

        format!(
            r#"#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct {name} {{
{fields}
}}

"#,
            name = pkt.name,
            fields = fields
        )
    }

    fn create_serialization_impl(pkt: &PacketExpr) -> String {
        let mut ser_body = String::new();
        for f in &pkt.fields {
            let endian = f.endianness.as_ref().or(pkt.endianness.as_ref()).unwrap_or(&Endianness::Le);
            ser_body.push_str(&emit_field_serialize(&f.id, &f.expr, endian.clone()));
        }

        let mut de_body = String::new();
        for (i, f) in pkt.fields.iter().enumerate() {
            let endian = f.endianness.as_ref().or(pkt.endianness.as_ref()).unwrap_or(&Endianness::Le);
            let last = i + 1 == pkt.fields.len();
            de_body.push_str(&emit_field_deserialize(&f.id, &f.expr, endian.clone(), last));
        }

        // calculated fields
        let mut calc_lets = String::new();
        for cf in &pkt.calculated_fields {
            let expr = emit_rust_numeric_expr(&cf.expr, /*root*/ "");
            let cast = rust_type_from_type_name(&cf.data_type);
            let _ = writeln!(
                &mut calc_lets,
                "        let {name}: {ty} = ({expr}) as {ty};",
                name = cf.name,
                ty = cast,
                expr = expr
            );
        }

        let mut build_fields = String::new();
        for f in &pkt.fields {
            let _ = writeln!(&mut build_fields, "            {name},", name = f.id);
        }
        for cf in &pkt.calculated_fields {
            let _ = writeln!(&mut build_fields, "            {name},", name = cf.name);
        }

        format!(
            r#"impl {name} {{
    pub fn serialize(&self) -> Vec<u8> {{
        let mut data: Vec<u8> = Vec::new();
{ser_body}
        data
    }}

    pub fn deserialize(data: &[u8]) -> {name} {{
        let mut cur = Cursor::new(data);

{de_body}{calc_lets}
        {name} {{
{build_fields}        }}
    }}
}}

"#,
            name = pkt.name,
            ser_body = indent(&ser_body, 2),
            de_body = indent(&de_body, 2),
            calc_lets = calc_lets,
            build_fields = build_fields
        )
    }
}

/* =====================================
 * Type mapping helpers
 * ===================================== */

fn rust_field_type(t: &TypeNode) -> String {
    use TypeNode::*;
    match t {
        // numeric families → scalar or Vec
        UnsignedInteger8(len) => if len.is_some() { "Vec<u8>".into() } else { "u8".into() },
        Integer8(len)         => if len.is_some() { "Vec<i8>".into() } else { "i8".into() },
        UnsignedInteger16(len)=> if len.is_some() { "Vec<u16>".into() } else { "u16".into() },
        Integer16(len)        => if len.is_some() { "Vec<i16>".into() } else { "i16".into() },
        UnsignedInteger32(len)=> if len.is_some() { "Vec<u32>".into() } else { "u32".into() },
        Integer32(len)        => if len.is_some() { "Vec<i32>".into() } else { "i32".into() },
        UnsignedInteger64(len)=> if len.is_some() { "Vec<u64>".into() } else { "u64".into() },
        Integer64(len)        => if len.is_some() { "Vec<i64>".into() } else { "i64".into() },
        Float32(len)          => if len.is_some() { "Vec<f32>".into() } else { "f32".into() },
        Float64(len)          => if len.is_some() { "Vec<f64>".into() } else { "f64".into() },
        DateTime(len)         => if len.is_some() { "Vec<i64>".into() } else { "i64".into() },

        Bytes(_len)           => "Vec<u8>".into(),
        MacAddress(len)       => if len.is_some() { "Vec<u8>".into() } else { "[u8; 6]".into() },
    }
}

fn rust_type_from_type_name(name: &str) -> &'static str {
    match name {
        "int8" => "i8",
        "uint8" => "u8",
        "int16" => "i16",
        "uint16" => "u16",
        "int32" => "i32",
        "uint32" => "u32",
        "int64" => "i64",
        "uint64" => "u64",
        "float32" => "f32",
        "float64" => "f64",
        "datetime" => "i64",
        "bytes" => "Vec<u8>",
        "macaddress" => "[u8; 6]",
        _ => "f64", // safe numeric fallback for calculated fields
    }
}

fn endian_ident(e: Endianness) -> &'static str {
    match e {
        Endianness::Le => "LittleEndian",
        Endianness::Be => "BigEndian",
    }
}

fn elem_size_bytes(t: &TypeNode) -> usize {
    use TypeNode::*;
    match t {
        UnsignedInteger8(_) | Integer8(_) => 1,
        UnsignedInteger16(_) | Integer16(_) => 2,
        UnsignedInteger32(_) | Integer32(_) | Float32(_) => 4,
        UnsignedInteger64(_) | Integer64(_) | Float64(_) | DateTime(_) => 8,
        Bytes(_) | MacAddress(_) => 1,
    }
}

/* =====================================
 * Field (de)serialization emitters
 * ===================================== */

fn emit_field_serialize(name: &str, t: &TypeNode, e: Endianness) -> String {
    let mut s = String::new();
    let ee = endian_ident(e);

    match t {
        // raw byte blobs
        TypeNode::Bytes(_) => {
            let _ = writeln!(&mut s, "(&mut data).write_all(&self.{name}).unwrap();");
        }
        TypeNode::MacAddress(len) => {
            if len.is_some() {
                let _ = writeln!(&mut s, "(&mut data).write_all(&self.{name}).unwrap();");
            } else {
                let _ = writeln!(&mut s, "(&mut data).write_all(&self.{name}).unwrap(); // 6 bytes");
            }
        }

        // numeric families
        _ => {
            let write_scalar = |dst: &mut String, expr: String, t: &TypeNode| {
                match t {
                    TypeNode::UnsignedInteger8(_) => {
                        let _ = writeln!(dst, "(&mut data).write_u8({expr}).unwrap();");
                    }
                    TypeNode::Integer8(_) => {
                        let _ = writeln!(dst, "(&mut data).write_i8({expr}).unwrap();");
                    }
                    TypeNode::UnsignedInteger16(_) => {
                        let _ = writeln!(dst, "(&mut data).write_u16::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::Integer16(_) => {
                        let _ = writeln!(dst, "(&mut data).write_i16::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::UnsignedInteger32(_) => {
                        let _ = writeln!(dst, "(&mut data).write_u32::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::Integer32(_) => {
                        let _ = writeln!(dst, "(&mut data).write_i32::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::UnsignedInteger64(_) => {
                        let _ = writeln!(dst, "(&mut data).write_u64::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::Integer64(_) | TypeNode::DateTime(_) => {
                        let _ = writeln!(dst, "(&mut data).write_i64::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::Float32(_) => {
                        let _ = writeln!(dst, "(&mut data).write_f32::<{ee}>({expr}).unwrap();");
                    }
                    TypeNode::Float64(_) => {
                        let _ = writeln!(dst, "(&mut data).write_f64::<{ee}>({expr}).unwrap();");
                    }
                    _ => {}
                }
            };

            if is_array_like(t) {
                let _ = writeln!(&mut s, "for v in &self.{name} {{");
                write_scalar(&mut s, " *v".into(), t);
                let _ = writeln!(&mut s, "}}");
            } else {
                write_scalar(&mut s, format!("self.{name}"), t);
            }
        }
    }

    s
}

fn emit_field_deserialize(name: &str, t: &TypeNode, e: Endianness, is_last: bool) -> String {
    let mut s = String::new();
    let ee = endian_ident(e);
    let w = elem_size_bytes(t);

    match t {
        // byte blobs
        TypeNode::Bytes(len_opt) => {
            if let Some(expr) = len_opt {
                let expr_s = emit_rust_len_expr(expr);
                let _ = writeln!(
                    &mut s,
                    "let mut {name}: Vec<u8> = vec![0u8; ({expr}) as usize]; cur.read_exact(&mut {name}).unwrap();",
                    expr = expr_s
                );
            } else if is_last {
                let _ = writeln!(
                    &mut s,
                    "let mut {name}: Vec<u8> = Vec::new(); cur.read_to_end(&mut {name}).unwrap();"
                );
            } else {
                let _ = writeln!(
                    &mut s,
                    r#"let {name}: Vec<u8> = Vec::new(); // WARNING: open-ended bytes not at end"#,
                );
            }
        }
        TypeNode::MacAddress(len_opt) => {
            if let Some(expr) = len_opt {
                let expr_s = emit_rust_len_expr(expr);
                let _ = writeln!(
                    &mut s,
                    "let mut {name}: Vec<u8> = vec![0u8; ({expr}) as usize]; cur.read_exact(&mut {name}).unwrap();",
                    expr = expr_s
                );
            } else {
                let _ = writeln!(
                    &mut s,
                    "let mut {name}: [u8; 6] = [0u8; 6]; cur.read_exact(&mut {name}).unwrap();"
                );
            }
        }

        // numeric families
        _ => {
            let read_scalar = |dst: &mut String, lhs: String, t: &TypeNode| {
                match t {
                    TypeNode::UnsignedInteger8(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_u8().unwrap();");
                    }
                    TypeNode::Integer8(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_i8().unwrap();");
                    }
                    TypeNode::UnsignedInteger16(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_u16::<{ee}>().unwrap();");
                    }
                    TypeNode::Integer16(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_i16::<{ee}>().unwrap();");
                    }
                    TypeNode::UnsignedInteger32(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_u32::<{ee}>().unwrap();");
                    }
                    TypeNode::Integer32(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_i32::<{ee}>().unwrap();");
                    }
                    TypeNode::UnsignedInteger64(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_u64::<{ee}>().unwrap();");
                    }
                    TypeNode::Integer64(_) | TypeNode::DateTime(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_i64::<{ee}>().unwrap();");
                    }
                    TypeNode::Float32(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_f32::<{ee}>().unwrap();");
                    }
                    TypeNode::Float64(_) => {
                        let _ = writeln!(dst, "let {lhs} = cur.read_f64::<{ee}>().unwrap();");
                    }
                    _ => {}
                }
            };

            if is_array_like(t) {
                if let Some(expr) = type_len_expr(t) {
                    let expr_s = emit_rust_len_expr(expr);
                    let rust_ty = base_scalar_rust(t);
                    let _ = writeln!(
                        &mut s,
                        "let mut {name}: Vec<{ty}> = Vec::with_capacity(({expr}) as usize);",
                        ty = rust_ty,
                        expr = expr_s
                    );
                    let _ = writeln!(&mut s, "for _ in 0..(({expr}) as usize) {{", expr = expr_s);
                    read_scalar(&mut s, "_tmp".into(), t);
                    let _ = writeln!(&mut s, "    {name}.push(_tmp);");
                    let _ = writeln!(&mut s, "}}");
                } else if is_last {
                    let rust_ty = base_scalar_rust(t);
                    let _ = writeln!(
                        &mut s,
                        "let remain = (cur.get_ref().len() as u64 - cur.position()) as usize;"
                    );
                    let _ = writeln!(
                        &mut s,
                        "let count = remain / {w}; let mut {name}: Vec<{ty}> = Vec::with_capacity(count);",
                        ty = rust_ty
                    );
                    let _ = writeln!(&mut s, "for _ in 0..count {{");
                    read_scalar(&mut s, "_tmp".into(), t);
                    let _ = writeln!(&mut s, "    {name}.push(_tmp);");
                    let _ = writeln!(&mut s, "}}");
                } else {
                    let rust_ty = base_scalar_rust(t);
                    let _ = writeln!(
                        &mut s,
                        "let {name}: Vec<{ty}> = Vec::new(); // WARNING: dynamic length without expr and not last",
                        ty = rust_ty
                    );
                }
            } else {
                read_scalar(&mut s, format!("{name}"), t);
            }
        }
    }

    s
}

/* =====================================
 * Expr emitters (for counts & calculated)
 * ===================================== */

fn emit_rust_len_expr(e: &ExprNode) -> String {
    // Produce a numeric Rust expression usable in `as usize` contexts.
    // We primarily emit as f64 math and cast to usize at use sites.
    emit_rust_numeric_expr(e, "")
}

fn emit_rust_numeric_expr(e: &ExprNode, _root: &str) -> String {
    use ExprNode::*;
    match e {
        UnsignedInteger64Value(u) => format!("({}f64)", *u as f64),
        Integer64Value(i) => format!("({}f64)", *i as f64),
        Float64Value(f) => format!("({})", f),

        StringValue(_) => "0.0".into(), // not expected in sizes

        ValueReference(name, idx) => {
            if let Some(ix) = idx {
                format!("({name}[({ix}) as usize] as f64)", ix = emit_rust_numeric_expr(ix, ""))
            } else {
                format!("({name} as f64)")
            }
        }

        ParenthesizedExpr(x) => format!("({})", emit_rust_numeric_expr(x, "")),

        Plus(a, b) => format!("({} + {})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Minus(a, b) => format!("({} - {})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Mult(a, b) => format!("({} * {})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Div(a, b) => format!("({} / {})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Pow(a, b) => format!("({}).powf({})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),

        // comparisons/logic → booleans; map to 1.0/0.0 to keep expression numeric
        Gt(a, b) => format!("(if {} > {} {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Gte(a, b)=> format!("(if {} >= {} {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Lt(a, b) => format!("(if {} < {} {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Lte(a, b)=> format!("(if {} <= {} {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Equals(a,b)=> format!("(if ({} - {}).abs() < 1e-9 {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        NotEquals(a,b)=> format!("(if ({} - {}).abs() >= 1e-9 {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        And(a, b) => format!("(if ({} != 0.0) && ({} != 0.0) {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),
        Or(a, b)  => format!("(if ({} != 0.0) || ({} != 0.0) {{ 1.0 }} else {{ 0.0 }})", emit_rust_numeric_expr(a, ""), emit_rust_numeric_expr(b, "")),

        ActivationRecord(name, args) => {
            let args_s: Vec<String> = args.iter().map(|a| emit_rust_numeric_expr(a, "")).collect();
            match name.as_str() {
                "sqrt" => format!("({}).sqrt()", args_s[0]),
                "min"  => format!("{}.min({})", args_s[0], args_s[1]),
                "max"  => format!("{}.max({})", args_s[0], args_s[1]),
                _ => "0.0".into(),
            }
        }

        GuardExpression(c, t, f) => format!(
            "(if {} != 0.0 {{ {} }} else {{ {} }})",
            emit_rust_numeric_expr(c, ""),
            emit_rust_numeric_expr(t, ""),
            emit_rust_numeric_expr(f, "")
        ),

        AggregateSum(_)
        | AggregateProduct(_) => "0.0".into(),

        NoExpr => "0.0".into(),
    }
}

/* =====================================
 * Utility predicates & helpers
 * ===================================== */

fn is_array_like(t: &TypeNode) -> bool {
    use TypeNode::*;
    match t {
        Bytes(_) | MacAddress(_) => true,
        UnsignedInteger8(e)
        | Integer8(e)
        | UnsignedInteger16(e)
        | Integer16(e)
        | UnsignedInteger32(e)
        | Integer32(e)
        | UnsignedInteger64(e)
        | Integer64(e)
        | Float32(e)
        | Float64(e)
        | DateTime(e) => e.is_some(),
    }
}

fn base_scalar_rust(t: &TypeNode) -> &'static str {
    use TypeNode::*;
    match t {
        UnsignedInteger8(_) => "u8",
        Integer8(_) => "i8",
        UnsignedInteger16(_) => "u16",
        Integer16(_) => "i16",
        UnsignedInteger32(_) => "u32",
        Integer32(_) => "i32",
        UnsignedInteger64(_) => "u64",
        Integer64(_) | DateTime(_) => "i64",
        Float32(_) => "f32",
        Float64(_) => "f64",
        Bytes(_) | MacAddress(_) => "u8",
    }
}

fn type_len_expr<'a>(t: &'a TypeNode) -> Option<&'a ExprNode> {
    use TypeNode::*;
    match t {
        Bytes(e) | MacAddress(e) => e.as_ref(),
        UnsignedInteger8(e)
        | Integer8(e)
        | UnsignedInteger16(e)
        | Integer16(e)
        | UnsignedInteger32(e)
        | Integer32(e)
        | UnsignedInteger64(e)
        | Integer64(e)
        | Float32(e)
        | Float64(e)
        | DateTime(e) => e.as_ref(),
    }
}

fn indent(s: &str, tabs: usize) -> String {
    let pad = "    ".repeat(tabs);
    s.lines()
        .map(|l| if l.is_empty() { "\n".to_string() } else { format!("{pad}{l}\n") })
        .collect()
}
