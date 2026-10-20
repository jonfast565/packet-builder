//! C identifiers and types.

use std::collections::HashSet;

use crate::generators::common::Dialect;
use crate::ir::{Member, Packet, ValueType, storage_for};

const KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "bool",
    "true",
    "false",
    "class",
    "new",
    "delete",
    "this",
    "template",
    "typename",
    "namespace",
    "private",
    "public",
    "protected",
    "virtual",
    "operator",
    "friend",
];

pub fn ident(name: &str) -> String {
    if KEYWORDS.contains(&name) { format!("{}_", name) } else { name.to_string() }
}

/// Name of the `size_t` member holding an array's element count.
pub fn len_ident(p: &Packet, member: &Member) -> String {
    let taken: HashSet<String> = p.members.iter().map(|m| ident(&m.name)).collect();
    let candidate = format!("{}_len", ident(&member.name));
    if taken.contains(&candidate) { format!("{}_pb_len", ident(&member.name)) } else { candidate }
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}int{}_t", if *signed { "" } else { "u" }, storage_for(*width))
        }
        ValueType::Float { width: 32 } => "float".into(),
        ValueType::Float { .. } => "double".into(),
        ValueType::Mac => "uint8_t".into(),
        ValueType::Packet(n) | ValueType::Union(n) => n.clone(),
        ValueType::Str => "char".into(),
    }
}

/// Suffix of the runtime array helpers for an element type.
pub fn helper_suffix(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}{}", if *signed { "i" } else { "u" }, storage_for(*width))
        }
        ValueType::Float { width } => format!("f{}", width),
        _ => "u8".into(),
    }
}

pub struct C;

impl Dialect for C {
    const TRUE: &'static str = "1";
    const FALSE: &'static str = "0";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p->{}", ident(&member.name))
    }
}
