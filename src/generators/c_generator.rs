use crate::models::parsing_models::{ExprNode, PacketExpr, PacketExprList, TypeExpr, TypeNode};
use tera::{Context, Tera};

pub struct CGenerator;

impl CGenerator {
    pub fn generate(model: &PacketExprList) -> String {
        // 1) Prepare Tera with inline templates
        let mut tera = Tera::default();
        tera.add_raw_template(
            "c_headers",
            include_str!("../../templates/c/c_headers.tera"),
        )
        .unwrap();
        tera.add_raw_template("c_root", include_str!("../../templates/c/c.tera"))
            .unwrap();
        tera.add_raw_template(
            "c_support",
            include_str!("../../templates/c/c_support.tera"),
        )
        .unwrap();

        // 2) Build context
        let headers = tera.render("c_headers", &Context::new()).unwrap();
        let support = tera.render("c_support", &Context::new()).unwrap();

        // Precompute per-packet code blocks
        let mut packets_ctx = Vec::<PacketCtx>::new();
        for pkt in &model.packets {
            packets_ctx.push(build_packet_ctx(pkt));
        }

        let mut ctx = Context::new();
        ctx.insert("headers", &headers);
        ctx.insert("support", &support);
        ctx.insert("packets", &packets_ctx);

        // 3) Render
        tera.render("c_root", &ctx).expect("Tera render failed")
    }
}

#[derive(serde::Serialize)]
struct PacketCtx {
    name: String,
    fields: Vec<FieldCtx>,
    total_size_code: String,
    serialize_body: String,
    deserialize_body: String,
}

#[derive(serde::Serialize)]
struct FieldCtx {
    decl: String, // e.g. "uint16_t foo[3]" or "uint8_t* data"
}

fn build_packet_ctx(pkt: &PacketExpr) -> PacketCtx {
    // 1) Struct declarations
    let mut fields_ctx = Vec::<FieldCtx>::new();

    // 2) Bodies and size-calculation snippets
    let mut total_size_code = String::new();
    let mut serialize_body = String::new();
    let mut deserialize_body = String::new();

    for field in &pkt.fields {
        // Declaration
        let decl = c_field_decl(field);
        fields_ctx.push(FieldCtx { decl });

        // Size calc + ser/de
        let (size_snip, ser_snip, de_snip) = codegen_field_snippets(field);
        total_size_code.push_str(&size_snip);
        serialize_body.push_str(&ser_snip);
        deserialize_body.push_str(&de_snip);
    }

    PacketCtx {
        name: pkt.name.clone(),
        fields: fields_ctx,
        total_size_code,
        serialize_body,
        deserialize_body,
    }
}

fn c_field_decl(field: &TypeExpr) -> String {
    let base = c_scalar_type(&field.expr);
    let arr = array_decl(&field.expr);
    format!("{} {}{}", base, field.id, arr)
}

/// Returns (size_calc, serialize, deserialize) snippets.
fn codegen_field_snippets(field: &TypeExpr) -> (String, String, String) {
    use TypeNode::*;
    let name = &field.id;
    let width = scalar_width_bytes(&field.expr);

    // Helpers to generate copy for a single element (scalar)
    let ser_scalar = |n: &str, w: usize| -> String {
        match w {
            1 => format!("(*data)[pos] = (uint8_t)(packet->{n}); pos += 1;\n"),
            2 => format!("store_u16_be(&(*data)[pos], (uint16_t)(packet->{n})); pos += 2;\n"),
            4 => format!("store_u32_be(&(*data)[pos], (uint32_t)(packet->{n})); pos += 4;\n"),
            8 => format!("store_u64_be(&(*data)[pos], (uint64_t)(packet->{n})); pos += 8;\n"),
            6 => format!("memcpy(&(*data)[pos], packet->{n}, 6); pos += 6;\n"),
            _ => format!("memcpy(&(*data)[pos], &packet->{n}, {w}); pos += {w};\n"),
        }
    };
    let de_scalar = |n: &str, w: usize| -> String {
        match w {
            1 => format!("(*packet)->{n} = (uint8_t)(data[pos]); pos += 1;\n"),
            2 => format!("(*packet)->{n} = (uint16_t)load_u16_be(&data[pos]); pos += 2;\n"),
            4 => format!("(*packet)->{n} = (uint32_t)load_u32_be(&data[pos]); pos += 4;\n"),
            8 => format!("(*packet)->{n} = (uint64_t)load_u64_be(&data[pos]); pos += 8;\n"),
            6 => format!("memcpy((*packet)->{n}, &data[pos], 6); pos += 6;\n"),
            _ => format!("memcpy(&(*packet)->{n}, &data[pos], {w}); pos += {w};\n"),
        }
    };

    // Determine array-ness and element copy logic
    match &field.expr {
        Bytes(len_expr_opt) => {
            // bytes: width 1 per element
            if let Some(e) = len_expr_opt {
                let count = emit_c_expr(e);
                let size = format!("total_size += (size_t)({count});\n");
                let ser = format!(
                    "for (size_t i = 0; i < (size_t)({count}); ++i) {{ (*data)[pos++] = packet->{name}[i]; }}\n"
                );
                let de = format!(
                    "{{ size_t cnt = (size_t)({count}); /* caller must ensure space */\n\
                     \tmemcpy((*packet)->{name}, &data[pos], cnt);\n\
                     \tpos += cnt; }}\n"
                );
                return (size, ser, de);
            } else {
                // Unknown-length bytes -> cannot pre-add to total; comment + no-op
                let size = String::from(
                    "/* bytes field with unknown length: not added to total_size */\n",
                );
                let ser = format!(
                    "/* bytes {name}: unknown length at compile-time. Provide length expression in DSL. */\n"
                );
                let de = format!(
                    "/* bytes {name}: unknown length at compile-time. Provide length expression in DSL. */\n"
                );
                return (size, ser, de);
            }
        }

        MacAddress(len_opt) => {
            // Default 6 if None; if Some(expr) then treat as that many bytes
            if let Some(e) = len_opt {
                if let Some(n) = eval_len_const(e) {
                    let size = format!("total_size += {};\n", n * 1);
                    let ser = format!(
                        "for (size_t i = 0; i < {n}; ++i) {{ (*data)[pos++] = packet->{name}[i]; }}\n"
                    );
                    let de = format!("memcpy((*packet)->{name}, &data[pos], {n}); pos += {n};\n");
                    return (size, ser, de);
                } else {
                    let count = emit_c_expr(e);
                    let size = format!("total_size += (size_t)({count});\n");
                    let ser = format!(
                        "for (size_t i = 0; i < (size_t)({count}); ++i) {{ (*data)[pos++] = packet->{name}[i]; }}\n"
                    );
                    let de = format!(
                        "{{ size_t cnt = (size_t)({count}); memcpy((*packet)->{name}, &data[pos], cnt); pos += cnt; }}\n"
                    );
                    return (size, ser, de);
                }
            } else {
                let size = "total_size += 6;\n".to_string();
                let ser = format!("memcpy(&(*data)[pos], packet->{name}, 6); pos += 6;\n");
                let de = format!("memcpy((*packet)->{name}, &data[pos], 6); pos += 6;\n");
                return (size, ser, de);
            }
        }

        // All other numeric/floating/date types:
        Integer8(len)
        | UnsignedInteger8(len)
        | Integer16(len)
        | UnsignedInteger16(len)
        | Integer32(len)
        | UnsignedInteger32(len)
        | Integer64(len)
        | UnsignedInteger64(len)
        | Float32(len)
        | Float64(len)
        | DateTime(len) => {
            match len {
                None => {
                    // Scalar
                    let size = format!("total_size += {};\n", width);
                    let ser = ser_scalar(name, width);
                    let de = de_scalar(name, width);
                    (size, ser, de)
                }
                Some(expr) => {
                    if let Some(n) = eval_len_const(expr) {
                        // Fixed-size array
                        let size = format!("total_size += {};\n", n * width);
                        let ser = format!(
                            "for (size_t i = 0; i < {n}; ++i) {{\n  {}\
                             }}\n",
                            ser_elem(name, width, "i")
                        );
                        let de = format!(
                            "for (size_t i = 0; i < {n}; ++i) {{\n  {}\
                             }}\n",
                            de_elem(name, width, "i")
                        );
                        (size, ser, de)
                    } else {
                        // Dynamic-size array driven by expression
                        let count = emit_c_expr(expr);
                        let size = format!("total_size += (size_t)({count}) * {};\n", width);
                        let ser = format!(
                            "for (size_t i = 0; i < (size_t)({count}); ++i) {{\n  {}\
                             }}\n",
                            ser_elem(name, width, "i")
                        );
                        let de = format!(
                            "for (size_t i = 0; i < (size_t)({count}); ++i) {{\n  {}\
                             }}\n",
                            de_elem(name, width, "i")
                        );
                        (size, ser, de)
                    }
                }
            }
        }
    }
}

fn ser_elem(name: &str, width: usize, idx: &str) -> String {
    match width {
        1 => format!("(*data)[pos++] = (uint8_t)(packet->{name}[{idx}]);\n"),
        2 => format!("store_u16_be(&(*data)[pos], (uint16_t)(packet->{name}[{idx}])); pos += 2;\n"),
        4 => format!("store_u32_be(&(*data)[pos], (uint32_t)(packet->{name}[{idx}])); pos += 4;\n"),
        8 => format!("store_u64_be(&(*data)[pos], (uint64_t)(packet->{name}[{idx}])); pos += 8;\n"),
        6 => format!("memcpy(&(*data)[pos], &packet->{name}[{idx}], 6); pos += 6;\n"),
        w => format!("memcpy(&(*data)[pos], &packet->{name}[{idx}], {w}); pos += {w};\n"),
    }
}
fn de_elem(name: &str, width: usize, idx: &str) -> String {
    match width {
        1 => format!("(*packet)->{name}[{idx}] = (uint8_t)(data[pos]); pos += 1;\n"),
        2 => format!("(*packet)->{name}[{idx}] = (uint16_t)load_u16_be(&data[pos]); pos += 2;\n"),
        4 => format!("(*packet)->{name}[{idx}] = (uint32_t)load_u32_be(&data[pos]); pos += 4;\n"),
        8 => format!("(*packet)->{name}[{idx}] = (uint64_t)load_u64_be(&data[pos]); pos += 8;\n"),
        6 => format!("memcpy(&(*packet)->{name}[{idx}], &data[pos], 6); pos += 6;\n"),
        w => format!("memcpy(&(*packet)->{name}[{idx}], &data[pos], {w}); pos += {w};\n"),
    }
}

fn c_scalar_type(t: &TypeNode) -> &'static str {
    use TypeNode::*;
    match t {
        UnsignedInteger8(_) => "uint8_t",
        Integer8(_) => "int8_t",
        UnsignedInteger16(_) => "uint16_t",
        Integer16(_) => "int16_t",
        UnsignedInteger32(_) => "uint32_t",
        Integer32(_) => "int32_t",
        UnsignedInteger64(_) => "uint64_t",
        Integer64(_) => "int64_t",
        Float32(_) => "float",
        Float64(_) => "double",
        DateTime(_) => "uint64_t",  // represent as epoch micros/nanos etc.
        MacAddress(_) => "uint8_t", // special-case array_decl below
        Bytes(_) => "uint8_t",
    }
}

fn scalar_width_bytes(t: &TypeNode) -> usize {
    use TypeNode::*;
    match t {
        UnsignedInteger8(_) | Integer8(_) => 1,
        UnsignedInteger16(_) | Integer16(_) => 2,
        UnsignedInteger32(_) | Integer32(_) | Float32(_) => 4,
        UnsignedInteger64(_) | Integer64(_) | Float64(_) | DateTime(_) => 8,
        MacAddress(_) => 1, // element width for array_decl; total handled separately where needed
        Bytes(_) => 1,
    }
}

fn array_decl(t: &TypeNode) -> String {
    use TypeNode::*;
    match t {
        MacAddress(len_opt) => {
            if let Some(e) = len_opt {
                if let Some(n) = eval_len_const(e) {
                    format!("[{}]", n)
                } else {
                    String::from("*")
                }
            } else {
                String::from("[6]")
            }
        }
        Bytes(len_opt) => {
            if let Some(e) = len_opt {
                if let Some(n) = eval_len_const(e) {
                    format!("[{}]", n)
                } else {
                    String::from("*")
                }
            } else {
                String::from("*")
            }
        }
        Integer8(len)
        | UnsignedInteger8(len)
        | Integer16(len)
        | UnsignedInteger16(len)
        | Integer32(len)
        | UnsignedInteger32(len)
        | Integer64(len)
        | UnsignedInteger64(len)
        | Float32(len)
        | Float64(len)
        | DateTime(len) => {
            match len {
                None => String::new(),
                Some(expr) => {
                    if let Some(n) = eval_len_const(expr) {
                        format!("[{}]", n)
                    } else {
                        String::from("*") // dynamic-size array -> pointer in C struct
                    }
                }
            }
        }
    }
}

fn eval_len_const(expr: &ExprNode) -> Option<usize> {
    eval_i128(expr).and_then(|n| if n >= 0 { Some(n as usize) } else { None })
}

fn eval_i128(e: &ExprNode) -> Option<i128> {
    use ExprNode::*;
    match e {
        UnsignedInteger64Value(u) => Some(*u as i128),
        Integer64Value(i) => Some(*i as i128),
        Float64Value(f) => Some(*f as i128),
        StringValue(_) => None,
        ParenthesizedExpr(inner) => eval_i128(inner),
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
            Some(ipow_i128(base, exp as u32)?)
        }
        // ternary/booleans unsupported for constant in general
        GuardExpression(_, _, _) => None,
        Gt(_, _)
        | Gte(_, _)
        | Lt(_, _)
        | Lte(_, _)
        | Equals(_, _)
        | NotEquals(_, _)
        | And(_, _)
        | Or(_, _) => None,
        ValueReference(_, _)
        | ActivationRecord(_, _)
        | AggregateSum(_)
        | AggregateProduct(_)
        | NoExpr => None,
    }
}
fn ipow_i128(mut base: i128, mut exp: u32) -> Option<i128> {
    let mut acc: i128 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc.checked_mul(base)?;
        }
        exp >>= 1;
        if exp > 0 {
            base = base.checked_mul(base)?;
        }
    }
    Some(acc)
}

fn emit_c_expr(e: &ExprNode) -> String {
    use ExprNode::*;
    match e {
        UnsignedInteger64Value(u) => format!("{}", u),
        Integer64Value(i) => format!("{}", i),
        Float64Value(f) => format!("{}", f),
        StringValue(s) => format!("\"{}\"", c_escape(s)),
        ValueReference(name, idx) => {
            if let Some(ix) = idx {
                format!("packet->{}[{}]", name, emit_c_expr(ix))
            } else {
                format!("packet->{}", name)
            }
        }
        ActivationRecord(fname, args) => {
            let mapped = match fname.as_str() {
                "sqrt" => "sqrt",
                "min" => "fmin",
                "max" => "fmax",
                _ => fname,
            };

            let args_s: Vec<String> = args.iter().map(|arg| emit_c_expr(arg)).collect();

            format!("{}({})", mapped, args_s.join(", "))
        }
        AggregateSum(id) => format!("0/*sumof({}) unsupported here*/", id),
        AggregateProduct(id) => format!("0/*productof({}) unsupported here*/", id),
        ParenthesizedExpr(inner) => format!("({})", emit_c_expr(inner)),
        GuardExpression(c, t, f) => format!(
            "({}) ? ({}) : ({})",
            emit_c_expr(c),
            emit_c_expr(t),
            emit_c_expr(f)
        ),
        Plus(a, b) => format!("({}) + ({})", emit_c_expr(a), emit_c_expr(b)),
        Minus(a, b) => format!("({}) - ({})", emit_c_expr(a), emit_c_expr(b)),
        Mult(a, b) => format!("({}) * ({})", emit_c_expr(a), emit_c_expr(b)),
        Div(a, b) => format!("({}) / ({})", emit_c_expr(a), emit_c_expr(b)),
        Pow(a, b) => format!(
            "ipow_u64((uint64_t)({}), (uint64_t)({}))",
            emit_c_expr(a),
            emit_c_expr(b)
        ),
        Gt(a, b) => format!("({}) > ({})", emit_c_expr(a), emit_c_expr(b)),
        Gte(a, b) => format!("({}) >= ({})", emit_c_expr(a), emit_c_expr(b)),
        Lt(a, b) => format!("({}) < ({})", emit_c_expr(a), emit_c_expr(b)),
        Lte(a, b) => format!("({}) <= ({})", emit_c_expr(a), emit_c_expr(b)),
        Equals(a, b) => format!("({}) == ({})", emit_c_expr(a), emit_c_expr(b)),
        NotEquals(a, b) => format!("({}) != ({})", emit_c_expr(a), emit_c_expr(b)),
        And(a, b) => format!("({}) && ({})", emit_c_expr(a), emit_c_expr(b)),
        Or(a, b) => format!("({}) || ({})", emit_c_expr(a), emit_c_expr(b)),
        NoExpr => "0".to_string(),
    }
}

fn c_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            _ => vec![c],
        })
        .collect()
}

