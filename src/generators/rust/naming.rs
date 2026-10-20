//! Rust identifiers and types.

use crate::generators::common::Dialect;
use crate::ir::{Member, Packet, ValueType, storage_for};

const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let",
    "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "trait", "true", "type",
    "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
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
        ValueType::Packet(n) | ValueType::Union(n) => n.clone(),
        ValueType::Str => "String".into(),
    }
}

pub fn member_type(m: &Member) -> String {
    match m.array {
        Some(_) => format!("Vec<{}>", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

/// How a module's types are spelled: owned, or (zero-copy) with byte
/// buffers and strings as `Cow`s that borrow the input, and a lifetime on
/// every packet and union that holds them.
pub struct Types {
    pub zero_copy: bool,
    pub borrowing: std::collections::HashSet<String>,
}

impl Types {
    pub fn new(module: &crate::ir::Module, zero_copy: bool) -> Self {
        let borrowing =
            if zero_copy { crate::generators::common::buffers::holding_buffers(module) } else { Default::default() };
        Types { zero_copy, borrowing }
    }

    /// `<'a>` after a packet or union that borrows the input.
    pub fn generics(&self, name: &str) -> &'static str {
        if self.borrowing.contains(name) { "<'a>" } else { "" }
    }

    pub fn elem(&self, ty: &ValueType) -> String {
        match ty {
            ValueType::Packet(n) | ValueType::Union(n) => format!("{}{}", n, self.generics(n)),
            ValueType::Str if self.zero_copy => "Cow<'a, str>".into(),
            t => scalar_type(t),
        }
    }

    /// A byte buffer's type.
    pub fn bytes(&self) -> &'static str {
        if self.zero_copy { "Cow<'a, [u8]>" } else { "Vec<u8>" }
    }

    pub fn member(&self, m: &Member) -> String {
        match m.array {
            Some(_) if m.ty.is_byte() => self.bytes().into(),
            Some(_) => format!("Vec<{}>", self.elem(&m.ty)),
            None => self.elem(&m.ty),
        }
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
