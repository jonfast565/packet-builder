//! TypeScript identifiers, types and default values.
//!
//! Integers of up to 32 bits are `number`s and wider ones `bigint`s; every
//! integer expression is a signed 64-bit `bigint`.

use crate::generators::common::{Dialect, magic_literal};
use crate::ir::{Member, Packet, ValueType};

/// Member names that would clash with the class's own members, or that a
/// class body reads as a modifier.
const MEMBER_RESERVED: &[&str] = &[
    "constructor",
    "encode",
    "encodeTo",
    "toJson",
    "__proto__",
    "static",
    "get",
    "set",
    "async",
    "declare",
    "readonly",
    "abstract",
    "public",
    "private",
    "protected",
    "override",
    "accessor",
];

/// Top-level names a packet, union or category cannot take: reserved words,
/// TypeScript's own type names and the globals the generated code uses.
const TYPE_RESERVED: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "as",
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
    "await",
    "any",
    "unknown",
    "never",
    "number",
    "bigint",
    "boolean",
    "string",
    "symbol",
    "object",
    "undefined",
    "type",
    "keyof",
    "infer",
    "is",
    "asserts",
    "readonly",
    "unique",
    "satisfies",
    "declare",
    "namespace",
    "module",
    "abstract",
    "arguments",
    "eval",
    "Array",
    "ArrayLike",
    "BigInt",
    "Boolean",
    "DataView",
    "Error",
    "Infinity",
    "JSON",
    "Math",
    "NaN",
    "Number",
    "Object",
    "Promise",
    "String",
    "Symbol",
    "TextDecoder",
    "TextEncoder",
    "Uint8Array",
    "PbError",
    "PbErrorKind",
    "PbReader",
    "PbWriter",
    "PbTrace",
    "PbFrame",
    "PbPlaced",
];

/// Constants of the runtime, which upper-case constant names must avoid.
const CONST_RESERVED: &[&str] = &["PB_MAX_DEPTH", "PB_MASK64", "PB_UTF8", "PB_UTF8_OUT", "PB_ENCODINGS", "PB_CRC"];

/// A member's property name.
pub fn ident(name: &str) -> String {
    if MEMBER_RESERVED.contains(&name) { format!("{}_", name) } else { name.to_string() }
}

/// The class, type or object name of a packet, union or category.
pub fn type_name(name: &str) -> String {
    if TYPE_RESERVED.contains(&name) || name.starts_with("pb") { format!("{}_", name) } else { name.to_string() }
}

/// A named constant: upper case, like the Python backend.
pub fn const_name(name: &str) -> String {
    let n = name.to_ascii_uppercase();
    if CONST_RESERVED.contains(&n.as_str()) { format!("{}_", n) } else { n }
}

/// True if values of `ty` are `bigint`s (integers wider than 32 bits).
pub fn is_big(ty: &ValueType) -> bool {
    matches!(ty, ValueType::Int { width, .. } if *width > 32)
}

/// The TypeScript type of one value of `ty`.
pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { .. } if is_big(ty) => "bigint".into(),
        ValueType::Int { .. } | ValueType::Float { .. } => "number".into(),
        ValueType::Mac => "Uint8Array".into(),
        ValueType::Str => "string".into(),
        ValueType::Packet(n) | ValueType::Union(n) => type_name(n),
    }
}

/// The TypeScript type of member `m`.
pub fn member_type(m: &Member) -> String {
    match &m.array {
        Some(_) if m.ty.is_byte() => "Uint8Array".into(),
        Some(_) => format!("{}[]", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

/// An integer literal of `ty`'s representation.
pub fn int_literal(v: &str, ty: &ValueType) -> String {
    if is_big(ty) { format!("{}n", v) } else { v.to_string() }
}

/// Zero of `ty` (`0`, `0n`).
pub fn zero(ty: &ValueType) -> &'static str {
    if is_big(ty) { "0n" } else { "0" }
}

/// The value a new instance's member starts with.
pub fn member_default(m: &Member) -> String {
    match &m.array {
        Some(_) if m.ty.is_byte() => "new Uint8Array(0)".into(),
        Some(_) => "[]".into(),
        None => match &m.ty {
            ValueType::Int { .. } => int_literal(&magic_literal(m).unwrap_or_else(|| "0".into()), &m.ty),
            ValueType::Float { .. } => "0".into(),
            ValueType::Mac => "new Uint8Array(6)".into(),
            ValueType::Packet(n) => format!("new {}()", type_name(n)),
            ValueType::Union(n) => format!("{}.pbDefault()", type_name(n)),
            ValueType::Str => "\"\"".into(),
        },
    }
}

/// `new Uint8Array([0x0d, 0x0a])`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("new Uint8Array([{}])", items.join(", "))
}

pub struct TypeScript;

impl Dialect for TypeScript {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", ident(&member.name))
    }
}
