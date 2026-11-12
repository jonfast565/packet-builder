//! Swift identifiers and types.

use std::collections::HashSet;

use crate::generators::common::{Dialect, pascal_case};
use crate::ir::{Arm, Member, Module, Packet, ValueType, storage_for};

/// Reserved words, escaped with backticks.
const KEYWORDS: &[&str] = &[
    "associatedtype",
    "class",
    "deinit",
    "enum",
    "extension",
    "fileprivate",
    "func",
    "import",
    "init",
    "inout",
    "internal",
    "let",
    "open",
    "operator",
    "private",
    "precedencegroup",
    "protocol",
    "public",
    "rethrows",
    "static",
    "struct",
    "subscript",
    "typealias",
    "var",
    "break",
    "case",
    "catch",
    "continue",
    "default",
    "defer",
    "do",
    "else",
    "fallthrough",
    "for",
    "guard",
    "if",
    "in",
    "repeat",
    "return",
    "throw",
    "switch",
    "where",
    "while",
    "Any",
    "as",
    "await",
    "false",
    "is",
    "nil",
    "throws",
    "true",
    "try",
    "async",
    "some",
    "any",
];

/// Names that cannot be members even in backticks (`p.Type` is the
/// metatype), and the names of the generated methods.
const RENAMED: &[&str] = &[
    "self",
    "Self",
    "super",
    "Type",
    "Protocol",
    "decode",
    "decodeFrom",
    "encode",
    "encodeTo",
    "toJson",
    "tryDecode",
    "frameLen",
];

/// Swift identifier for a member, arm or constant name.
pub fn ident(name: &str) -> String {
    match name {
        n if RENAMED.contains(&n) => format!("{}_", n),
        n if KEYWORDS.contains(&n) => format!("`{}`", n),
        n => n.to_string(),
    }
}

/// The enum case of a union arm: `keep_alive` → `keepAlive`.
pub fn case_name(arm: &Arm) -> String {
    let p = pascal_case(&arm.name);
    let mut chars = p.chars();
    let lower: String = match chars.next() {
        Some(c) => c.to_lowercase().chain(chars).collect(),
        None => p,
    };
    ident(&lower)
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}{}", if *signed { "Int" } else { "UInt" }, storage_for(*width))
        }
        ValueType::Float { width: 32 } => "Float".into(),
        ValueType::Float { .. } => "Double".into(),
        ValueType::Mac => "[UInt8]".into(),
        ValueType::Packet(n) | ValueType::Union(n) => n.clone(),
        ValueType::Str => "String".into(),
    }
}

/// How a module's types are spelled: byte buffers are `[UInt8]`, or
/// (zero-copy) `ArraySlice<UInt8>`s sharing the input's storage.
pub struct Types {
    pub zero_copy: bool,
    /// Packets and unions that hold byte buffers (documented as sharing the input).
    pub borrowing: HashSet<String>,
}

impl Types {
    pub fn new(module: &Module, zero_copy: bool) -> Self {
        let borrowing =
            if zero_copy { crate::generators::common::buffers::holding_buffers(module) } else { Default::default() };
        Types { zero_copy, borrowing }
    }

    /// A byte buffer's type.
    pub fn bytes(&self) -> &'static str {
        if self.zero_copy { "ArraySlice<UInt8>" } else { "[UInt8]" }
    }

    pub fn member(&self, m: &Member) -> String {
        match m.array {
            Some(_) if m.ty.is_byte() => self.bytes().into(),
            Some(_) => format!("[{}]", scalar_type(&m.ty)),
            None => scalar_type(&m.ty),
        }
    }

    /// The type an arm holds.
    pub fn arm(&self, arm: &Arm) -> Option<String> {
        match (&arm.ty, arm.is_bytes()) {
            (None, _) => None,
            (Some(_), true) => Some(self.bytes().into()),
            (Some(t), false) => Some(scalar_type(t)),
        }
    }
}

/// The initial value of a type.
pub fn default_value(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { .. } | ValueType::Float { .. } => "0".into(),
        ValueType::Mac => "[0, 0, 0, 0, 0, 0]".into(),
        ValueType::Str => "\"\"".into(),
        ValueType::Packet(n) | ValueType::Union(n) => format!("{}()", n),
    }
}

/// The initial value of a member.
pub fn member_default(m: &Member) -> String {
    match m.array {
        Some(_) => "[]".into(),
        None => default_value(&m.ty),
    }
}

pub struct Swift;

impl Dialect for Swift {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", ident(&member.name))
    }
}
