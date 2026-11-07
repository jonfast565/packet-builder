//! Object Pascal identifiers and types.

use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, GenOptions, magic_literal, pascal_case, string_literal};
use crate::ir::{Arm, Member, Packet, ValueType, storage_for};

/// Names a field or constant must not take (compared in lower case, since
/// Pascal ignores case): reserved words, `TObject` members, the generated
/// methods, and the RTL names generated method bodies use, which a field of
/// the same name would hide.
const RESERVED: &[&str] = &[
    // reserved words (Delphi and FPC)
    "and",
    "array",
    "as",
    "asm",
    "begin",
    "case",
    "class",
    "const",
    "constructor",
    "destructor",
    "dispinterface",
    "div",
    "do",
    "downto",
    "else",
    "end",
    "except",
    "exports",
    "file",
    "finalization",
    "finally",
    "for",
    "function",
    "goto",
    "if",
    "implementation",
    "in",
    "inherited",
    "initialization",
    "inline",
    "interface",
    "is",
    "label",
    "library",
    "mod",
    "nil",
    "not",
    "object",
    "of",
    "operator",
    "or",
    "out",
    "packed",
    "procedure",
    "program",
    "property",
    "raise",
    "record",
    "repeat",
    "resourcestring",
    "set",
    "shl",
    "shr",
    "string",
    "then",
    "threadvar",
    "to",
    "try",
    "type",
    "unit",
    "until",
    "uses",
    "var",
    "while",
    "with",
    "xor",
    "self",
    "result",
    // TObject and the generated methods
    "create",
    "destroy",
    "free",
    "classname",
    "classtype",
    "classinfo",
    "classparent",
    "equals",
    "gethashcode",
    "tostring",
    "inheritsfrom",
    "fieldaddress",
    "dispatch",
    "instancesize",
    "newinstance",
    "freeinstance",
    "afterconstruction",
    "beforedestruction",
    "methodaddress",
    "methodname",
    "unitname",
    "decode",
    "decodefrom",
    "encode",
    "encodeto",
    "tojson",
    "trydecode",
    "framelen",
    "pbdefault",
    "value",
    // names the generated bodies use
    "p",
    "length",
    "high",
    "low",
    "setlength",
    "inc",
    "dec",
    "ord",
    "copy",
    "move",
    "exit",
    "break",
    "continue",
    "trunc",
    "sqrt",
    "int8",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "int64",
    "uint64",
    "single",
    "double",
    "char",
    "byte",
    "word",
    "integer",
    "cardinal",
    "boolean",
    "true",
    "false",
    "freeandnil",
    "inttostr",
    "assigned",
    "tbytes",
    "exception",
];

/// A field or constant name: PascalCase, with `_` after reserved names.
pub fn ident(name: &str) -> String {
    let n = pascal_case(name);
    let lower = n.to_ascii_lowercase();
    if RESERVED.contains(&lower.as_str()) || lower.starts_with("pb") { format!("{}_", n) } else { n }
}

/// The class of packet or union `name` (`TMessage`).
pub fn type_name(name: &str) -> String {
    format!("T{}", name)
}

/// The class of an arm of union `union` (`TMessageBody_Ping`).
pub fn arm_class(union: &str, arm: &Arm) -> String {
    format!("T{}_{}", union, variant_name(arm))
}

/// The unit name: the package, made an identifier (the file is
/// `<package>.pas`, and FPC wants the unit named like its file).
pub fn unit_name(opts: &GenOptions) -> String {
    let mut n: String = opts.package.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit()) {
        n.insert(0, 'U');
    }
    n
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}Int{}", if *signed { "" } else { "U" }, storage_for(*width))
        }
        ValueType::Float { width: 32 } => "Single".into(),
        ValueType::Float { .. } => "Double".into(),
        ValueType::Mac => "TBytes".into(),
        ValueType::Packet(n) | ValueType::Union(n) => type_name(n),
        ValueType::Str => "string".into(),
    }
}

/// The dynamic array type of `ty` elements (runtime types, or
/// `T<Packet>Array` declared with the packets).
pub fn array_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed: false } if storage_for(*width) == 8 => "TBytes".into(),
        ValueType::Int { width, signed } => {
            format!("TPb{}Int{}Array", if *signed { "" } else { "U" }, storage_for(*width))
        }
        ValueType::Float { width: 32 } => "TPbSingleArray".into(),
        ValueType::Float { .. } => "TPbDoubleArray".into(),
        ValueType::Mac => "TPbBytesArray".into(),
        ValueType::Str => "TPbStringArray".into(),
        ValueType::Packet(n) | ValueType::Union(n) => format!("T{}Array", n),
    }
}

pub fn member_type(m: &Member) -> String {
    match m.array {
        Some(_) => array_type(&m.ty),
        None => scalar_type(&m.ty),
    }
}

/// True for members holding objects the packet owns (and frees).
pub fn owns_objects(m: &Member) -> bool {
    matches!(m.ty, ValueType::Packet(_) | ValueType::Union(_))
}

/// What the constructor sets a member to, if anything.
pub fn default_value(m: &Member) -> Option<String> {
    match (&m.array, &m.ty) {
        (Some(_), _) => None,
        (None, ValueType::Mac) => Some("PbZeros(6)".into()),
        (None, ValueType::Packet(n)) => Some(format!("{}.Create", type_name(n))),
        (None, ValueType::Union(n)) => Some(format!("{}.PbDefault", type_name(n))),
        (None, ValueType::Str) => None,
        _ => magic_literal(m).map(|v| format!("{}({})", scalar_type(&m.ty), v)),
    }
}

/// A Pascal string literal: `'it''s'`, from the same text the other
/// backends quote with [`string_literal`].
pub fn pas_string(text: &str) -> String {
    let quoted = string_literal(text);
    let inner = &quoted[1..quoted.len() - 1];
    let mut out = String::from("'");
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        let c = if c == '\\' { chars.next().unwrap_or('\\') } else { c };
        if c == '\'' {
            out.push('\'');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// `[$0D, $0A]`: an open array of bytes.
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("${:02X}", b)).collect();
    format!("[{}]", items.join(", "))
}

pub struct Pascal;

impl Dialect for Pascal {
    const TRUE: &'static str = "True";
    const FALSE: &'static str = "False";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", ident(&member.name))
    }
}
