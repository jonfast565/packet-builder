//! Zig identifiers, types and default values.

use crate::generators::common::{Dialect, magic_literal};
use crate::ir::{Member, Packet, ValueType};

const KEYWORDS: &[&str] = &[
    "addrspace",
    "align",
    "allowzero",
    "and",
    "anyframe",
    "anytype",
    "asm",
    "async",
    "await",
    "break",
    "callconv",
    "catch",
    "comptime",
    "const",
    "continue",
    "defer",
    "else",
    "enum",
    "errdefer",
    "error",
    "export",
    "extern",
    "fn",
    "for",
    "if",
    "inline",
    "linksection",
    "noalias",
    "noinline",
    "nosuspend",
    "opaque",
    "or",
    "orelse",
    "packed",
    "pub",
    "resume",
    "return",
    "struct",
    "suspend",
    "switch",
    "test",
    "threadlocal",
    "try",
    "union",
    "unreachable",
    "usingnamespace",
    "var",
    "volatile",
    "while",
    // primitive values and types
    "true",
    "false",
    "null",
    "undefined",
    "bool",
    "void",
    "type",
    "anyerror",
    "anyopaque",
    "noreturn",
    "isize",
    "usize",
    "comptime_int",
    "comptime_float",
    "f16",
    "f32",
    "f64",
    "f80",
    "f128",
    "c_char",
    "c_short",
    "c_ushort",
    "c_int",
    "c_uint",
    "c_long",
    "c_ulong",
    "c_longlong",
    "c_ulonglong",
    "c_longdouble",
    // declarations of every generated struct
    "decode",
    "decodeFrom",
    "encode",
    "encodeTo",
    "deinit",
];

/// Zig field name for a member.
pub fn ident(name: &str) -> String {
    let is_int_type = name.len() > 1
        && (name.starts_with('u') || name.starts_with('i'))
        && name[1..].chars().all(|c| c.is_ascii_digit());
    if KEYWORDS.contains(&name) || is_int_type { format!("@\"{}\"", name) } else { name.to_string() }
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => format!("{}{}", if *signed { "i" } else { "u" }, width),
        ValueType::Float { width } => format!("f{}", width),
        ValueType::Mac => "[6]u8".into(),
        ValueType::Packet(n) | ValueType::Union(n) => n.clone(),
        ValueType::Str => "[]const u8".into(),
    }
}

pub fn member_type(m: &Member) -> String {
    match m.array {
        Some(_) => format!("[]const {}", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

pub fn default_value(m: &Member) -> String {
    match (&m.array, &m.ty) {
        (Some(_), _) => "&.{}".into(),
        (None, ValueType::Int { .. }) => magic_literal(m).unwrap_or_else(|| "0".into()),
        (None, ValueType::Float { .. }) => "0".into(),
        (None, ValueType::Mac) => "[_]u8{0} ** 6".into(),
        (None, ValueType::Packet(_)) => ".{}".into(),
        (None, ValueType::Union(n)) => format!("{}.pb_default", n),
        (None, ValueType::Str) => "\"\"".into(),
    }
}

/// Members that own heap memory (and so need deinit).
/// Whether a decoded member owns memory `deinit` frees (zero-copy byte
/// buffers are slices of the input).
pub fn owns_memory(m: &Member, zero_copy: bool) -> bool {
    if zero_copy && m.array.is_some() && m.ty.is_byte() {
        return false;
    }
    m.array.is_some() || matches!(m.ty, ValueType::Packet(_) | ValueType::Str | ValueType::Union(_))
}

pub struct Zig;

impl Dialect for Zig {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", ident(&member.name))
    }
}
