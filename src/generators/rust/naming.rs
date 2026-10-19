//! Rust identifiers and types.

use crate::generators::common::Dialect;
use crate::ir::{Member, Packet, ValueType, storage_for};

const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let",
    "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "trait", "true", "type",
    "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
];

/// Rust identifier for a member name.
pub fn ident(name: &str) -> String {
    match name {
        "self" | "Self" | "super" | "crate" => format!("{}_", name),
        n if KEYWORDS.contains(&n) => format!("r#{}", n),
        n => n.to_string(),
    }
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}{}", if *signed { "i" } else { "u" }, storage_for(*width))
        }
        ValueType::Float { width } => format!("f{}", width),
        ValueType::Mac => "[u8; 6]".into(),
        ValueType::Packet(n) => n.clone(),
        ValueType::Str => "String".into(),
    }
}

pub fn member_type(m: &Member) -> String {
    match m.array {
        Some(_) => format!("Vec<{}>", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

pub struct Rust;

impl Dialect for Rust {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", ident(&member.name))
    }
}
