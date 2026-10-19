//! Python identifiers and type annotations.

use crate::generators::common::Dialect;
use crate::ir::{Member, Packet, ValueType};
use crate::models::parsing_models::Endianness;

const KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
    "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

pub fn ident(name: &str) -> String {
    if KEYWORDS.contains(&name) { format!("{}_", name) } else { name.to_string() }
}

pub fn annotation(m: &Member) -> String {
    let scalar = match &m.ty {
        ValueType::Int { .. } => "int".to_string(),
        ValueType::Float { .. } => "float".to_string(),
        ValueType::Mac => "bytes".to_string(),
        ValueType::Packet(n) => n.clone(),
        ValueType::Str => "str".to_string(),
    };
    match &m.array {
        Some(_) if m.ty.is_byte() => "bytes = b\"\"".into(),
        Some(_) => format!("List[{}] = field(default_factory=list)", scalar),
        None => match &m.ty {
            ValueType::Int { .. } => "int = 0".into(),
            ValueType::Float { .. } => "float = 0.0".into(),
            ValueType::Mac => "bytes = bytes(6)".into(),
            ValueType::Packet(n) => format!("{} = field(default_factory=lambda: {}())", n, n),
            ValueType::Str => "str = \"\"".into(),
        },
    }
}

pub struct Python;

impl Dialect for Python {
    const TRUE: &'static str = "True";
    const FALSE: &'static str = "False";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", ident(&member.name))
    }
}

/// `struct` module format of a float (`<f`, `>d`, ...).
pub fn float_format(width: u32, endian: &Endianness) -> String {
    format!("{}{}", if *endian == Endianness::Le { "<" } else { ">" }, if width == 32 { "f" } else { "d" })
}
