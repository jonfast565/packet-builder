use crate::models::parsing_models::{
    Endianness, ExprNode, PacketExpr, PacketExprList, TypeNode,
};
use std::fmt::Write as _;

pub struct PythonGenerator {}

impl PythonGenerator {
    pub fn generate(model: &PacketExprList) -> String {
        let mut out = String::new();
        out.push_str("import struct\nimport math\n\n\n");

        for pkt in &model.packets {
            out.push_str(&Self::build_class(pkt));
            out.push_str("\n\n");
        }
        out
    }

    fn build_class(pkt: &PacketExpr) -> String {
        let class_name = &pkt.name;

        // __init__ fields
        let mut init_body = String::new();
        for f in &pkt.fields {
            let default = py_default_value(&f.expr);
            let _ = writeln!(
                &mut init_body,
                "        self.{name} = {default}",
                name = f.id,
                default = default
            );
        }

        // to_bytes body (serialize)
        let mut ser_body = String::new();
        for f in &pkt.fields {
            let end = f.endianness.as_ref().or(pkt.endianness.as_ref()).unwrap_or(&Endianness::Le);
            ser_body.push_str(&serialize_snippet(&f.expr, &f.id, end.clone()));
        }

        // from_bytes body (deserialize)
        let mut de_body = String::new();
        let n = pkt.fields.len();
        for (i, f) in pkt.fields.iter().enumerate() {
            let last = i + 1 == n;
            let end = f.endianness.as_ref().or(pkt.endianness.as_ref()).unwrap_or(&Endianness::Le);
            de_body.push_str(&deserialize_snippet(&f.expr, &f.id, end.clone(), last));
        }

        format!(
r#"class {class_name}:
    def __init__(self):
{init_body}
    def to_bytes(self, verbose: bool = False) -> bytes:
        data = bytearray()
{ser_body}
        return bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes, verbose: bool = False) -> "{class_name}":
        result = cls()
        pos = 0
{de_body}
        return result
"#,
            class_name = class_name,
            init_body = init_body,
            ser_body = indent(&ser_body, 2),
            de_body = indent(&de_body, 2),
        )
    }
}

/* ============================================================
 * Python emission helpers
 * ============================================================
*/

fn py_endian_prefix(e: Endianness) -> &'static str {
    match e {
        Endianness::Le => "<",
        Endianness::Be => ">",
    }
}

fn scalar_struct_code(t: &TypeNode) -> Option<&'static str> {
    use TypeNode::*;
    Some(match t {
        UnsignedInteger8(_) => "B",
        Integer8(_) => "b",
        UnsignedInteger16(_) => "H",
        Integer16(_) => "h",
        UnsignedInteger32(_) => "I",
        Integer32(_) => "i",
        UnsignedInteger64(_) => "Q",
        Integer64(_) => "q",
        Float32(_) => "f",
        Float64(_) => "d",
        DateTime(_) => "q", // 64-bit signed on wire
        Bytes(_) | MacAddress(_) => return None,
    })
}

fn scalar_width_bytes(t: &TypeNode) -> usize {
    use TypeNode::*;
    match t {
        UnsignedInteger8(_) | Integer8(_) => 1,
        UnsignedInteger16(_) | Integer16(_) => 2,
        UnsignedInteger32(_) | Integer32(_) | Float32(_) => 4,
        UnsignedInteger64(_) | Integer64(_) | Float64(_) | DateTime(_) => 8,
        Bytes(_) | MacAddress(_) => 1,
    }
}

fn py_default_value(t: &TypeNode) -> String {
    use TypeNode::*;
    match t {
        Bytes(_) | MacAddress(_) => "b''".to_string(),
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
        | DateTime(len) => {
            if len.is_some() {
                "[]".to_string()
            } else {
                match t {
                    Float32(_) | Float64(_) => "0.0".to_string(),
                    _ => "0".to_string(),
                }
            }
        }
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

/* ============================================================
 * Serialization / Deserialization snippet generators
 * ============================================================
*/

fn serialize_snippet(t: &TypeNode, name: &str, endian: Endianness) -> String {
    let mut s = String::new();
    match t {
        TypeNode::Bytes(_) | TypeNode::MacAddress(_) => {
            // raw bytes
            let _ = writeln!(
                &mut s,
                "data += (self.{name} if isinstance(self.{name}, (bytes, bytearray)) else bytes(self.{name}))"
            );
        }
        _ => {
            let code = scalar_struct_code(t).expect("scalar code");
            let width = scalar_width_bytes(t);
            let prefix = py_endian_prefix(endian);

            if is_array_like(t) {
                // Loop; simple & robust for dynamic sizes
                let _ = writeln!(
                    &mut s,
                    "for _v in (self.{name} or []): data += struct.pack('{prefix}{code}', _v)"
                );
            } else {
                let _ = writeln!(
                    &mut s,
                    "data += struct.pack('{prefix}{code}', self.{name})"
                );
            }

            // avoid unused warnings in Python (none really, but keep style)
            let _ = width; // retained for parity with other gens
        }
    }
    s
}

fn deserialize_snippet(t: &TypeNode, name: &str, endian: Endianness, is_last: bool) -> String {
    let mut s = String::new();
    match t {
        TypeNode::Bytes(len_opt) => {
            if let Some(expr) = len_opt {
                let py = emit_py_expr(expr, "result");
                let _ = writeln!(
                    &mut s,
                    "count = int({py}) if {py} is not None else 0"
                );
                let _ = writeln!(
                    &mut s,
                    "result.{name} = bytes(data[pos:pos+count]); pos += count"
                );
            } else if is_last {
                let _ = writeln!(
                    &mut s,
                    "result.{name} = bytes(data[pos:]); pos = len(data)"
                );
            } else {
                let _ = writeln!(
                    &mut s,
                    "raise ValueError('Open-ended bytes field \"{name}\" must be last')"
                );
            }
        }
        TypeNode::MacAddress(len_opt) => {
            if let Some(expr) = len_opt {
                let py = emit_py_expr(expr, "result");
                let _ = writeln!(
                    &mut s,
                    "count = int({py}) if {py} is not None else 0"
                );
                let _ = writeln!(
                    &mut s,
                    "result.{name} = bytes(data[pos:pos+count]); pos += count"
                );
            } else {
                let _ = writeln!(
                    &mut s,
                    "result.{name} = bytes(data[pos:pos+6]); pos += 6"
                );
            }
        }
        _ => {
            let code = scalar_struct_code(t).expect("scalar code");
            let width = scalar_width_bytes(t);
            let prefix = py_endian_prefix(endian);

            if is_array_like(t) {
                if let Some(e) = type_len_expr(t) {
                    // Use expression for element count (can reference previously parsed fields)
                    let py = emit_py_expr(e, "result");
                    let _ = writeln!(
                        &mut s,
                        "count = int({py}) if {py} is not None else 0"
                    );
                    let _ = writeln!(&mut s, "result.{name} = []");
                    let _ = writeln!(
                        &mut s,
                        "for _ in range(count): _v, = struct.unpack_from('{prefix}{code}', data, pos); pos += {width}; result.{name}.append(_v)"
                    );
                } else if is_last {
                    // If somehow no expr, treat remaining bytes as array of given element width
                    let _ = writeln!(
                        &mut s,
                        "remain = len(data) - pos; count = remain // {width}; result.{name} = []"
                    );
                    let _ = writeln!(
                        &mut s,
                        "for _ in range(count): _v, = struct.unpack_from('{prefix}{code}', data, pos); pos += {width}; result.{name}.append(_v)"
                    );
                } else {
                    let _ = writeln!(
                        &mut s,
                        "raise ValueError('Dynamic-length array field \"{name}\" must be last or have an explicit expression')"
                    );
                }
            } else {
                let _ = writeln!(
                    &mut s,
                    "result.{name}, = struct.unpack_from('{prefix}{code}', data, pos); pos += {width}"
                );
            }
        }
    }
    s
}

/* ============================================================
 * Expr → Python emitter
 * ============================================================
*/

fn emit_py_expr(e: &ExprNode, root_ident: &str) -> String {
    use ExprNode::*;
    match e {
        UnsignedInteger64Value(u) => format!("{}", u),
        Integer64Value(i) => format!("{}", i),
        Float64Value(f) => format!("{}", f),
        StringValue(s) => format!("'{}'", py_escape(s)),
        ValueReference(name, idx) => {
            if let Some(ix) = idx {
                format!("{root}.{name}[{}]", emit_py_expr(ix, root_ident), root = root_ident, name = name)
            } else {
                format!("{root}.{name}", root = root_ident, name = name)
            }
        }
        ActivationRecord(fname, args) => {
            let mapped = match fname.as_str() {
                "sqrt" => "math.sqrt",
                "min" => "min",
                "max" => "max",
                _ => fname,
            };
            let args_s: Vec<String> = args.iter().map(|a| emit_py_expr(a, root_ident)).collect();
            format!("{}({})", mapped, args_s.join(", "))
        }
        AggregateSum(id) => format!("0  # sumof({}) unsupported in size expr", id),
        AggregateProduct(id) => format!("0  # productof({}) unsupported in size expr", id),
        ParenthesizedExpr(inner) => format!("({})", emit_py_expr(inner, root_ident)),
        GuardExpression(c, t, f) => format!(
            "({}) if ({}) else ({})",
            emit_py_expr(t, root_ident),
            emit_py_expr(c, root_ident),
            emit_py_expr(f, root_ident)
        ),

        Plus(a, b) => bin(a, b, "+", root_ident),
        Minus(a, b) => bin(a, b, "-", root_ident),
        Mult(a, b) => bin(a, b, "*", root_ident),
        Div(a, b) => bin(a, b, "/", root_ident),
        Pow(a, b) => format!(
            "int(pow({}, {}))",
            emit_py_expr(a, root_ident),
            emit_py_expr(b, root_ident)
        ),

        Gt(a, b) => bin(a, b, ">", root_ident),
        Gte(a, b) => bin(a, b, ">=", root_ident),
        Lt(a, b) => bin(a, b, "<", root_ident),
        Lte(a, b) => bin(a, b, "<=", root_ident),
        Equals(a, b) => bin(a, b, "==", root_ident),
        NotEquals(a, b) => bin(a, b, "!=", root_ident),
        And(a, b) => bin(a, b, "and", root_ident),
        Or(a, b) => bin(a, b, "or", root_ident),

        NoExpr => "0".to_string(),
    }
}

fn bin(a: &ExprNode, b: &ExprNode, op: &str, root_ident: &str) -> String {
    format!(
        "({}) {} ({})",
        emit_py_expr(a, root_ident),
        op,
        emit_py_expr(b, root_ident)
    )
}

fn py_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\'' => "\\'".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            _ => vec![c],
        })
        .collect()
}

/* ============================================================
 * Formatting helper
 * ============================================================
*/

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
