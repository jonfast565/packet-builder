//! Ada identifiers and types.

use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, GenOptions, magic_literal, string_literal};
use crate::ir::{Arm, Member, Packet, ValueType, storage_for};

/// Names a field, constant or type must not take (compared in lower case,
/// since Ada ignores case): reserved words, the packages and types the
/// generated code names, and the names of the generated subprograms and
/// their parameters.
const RESERVED: &[&str] = &[
    // Ada 2012 reserved words
    "abort",
    "abs",
    "abstract",
    "accept",
    "access",
    "aliased",
    "all",
    "and",
    "array",
    "at",
    "begin",
    "body",
    "case",
    "constant",
    "declare",
    "delay",
    "delta",
    "digits",
    "do",
    "else",
    "elsif",
    "end",
    "entry",
    "exception",
    "exit",
    "for",
    "function",
    "generic",
    "goto",
    "if",
    "in",
    "interface",
    "is",
    "limited",
    "loop",
    "mod",
    "new",
    "not",
    "null",
    "of",
    "or",
    "others",
    "out",
    "overriding",
    "package",
    "pragma",
    "private",
    "procedure",
    "protected",
    "raise",
    "range",
    "record",
    "rem",
    "renames",
    "requeue",
    "return",
    "reverse",
    "select",
    "separate",
    "some",
    "subtype",
    "synchronized",
    "tagged",
    "task",
    "terminate",
    "then",
    "type",
    "until",
    "use",
    "when",
    "while",
    "with",
    "xor",
    // packages and types the generated code names
    "kind",
    "interfaces",
    "ada",
    "standard",
    "system",
    "packets",
    "unsigned_8",
    "unsigned_16",
    "unsigned_32",
    "unsigned_64",
    "integer_8",
    "integer_16",
    "integer_32",
    "integer_64",
    "ieee_float_32",
    "ieee_float_64",
    "integer",
    "natural",
    "positive",
    "boolean",
    "true",
    "false",
    "character",
    "string",
    "float",
    "shift_left",
    "shift_right",
    "shift_right_arithmetic",
    "rotate_left",
    "rotate_right",
    // generated subprograms and their parameters
    "decode",
    "decode_from",
    "encode",
    "encode_to",
    "to_json",
    "try_decode",
    "length",
    "element",
    "append",
    "clear",
    "last_element",
    "last_error",
    "adjust",
    "finalize",
    "initialize",
    "data",
    "value",
    "taken",
    "size",
    "version",
    "items",
    "len",
    "p",
    "r",
    "w",
    "s",
    "e",
];

fn is_reserved(lower: &str) -> bool {
    RESERVED.contains(&lower) || lower.starts_with("pb")
}

/// `foo_bar` -> `Foo_Bar`: pieces split on `_` and `-`, each capitalised
/// (Ada allows neither leading, trailing nor doubled underscores).
fn mixed_case(name: &str) -> String {
    let pieces: Vec<String> = name
        .split(['_', '-'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                Some(f) => f.to_uppercase().chain(c).collect(),
                None => String::new(),
            }
        })
        .collect();
    pieces.join("_")
}

/// A field, arm or constant name: Mixed_Case, `_F` after reserved names.
pub fn ident(name: &str) -> String {
    let mut n = mixed_case(name);
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit()) {
        n.insert_str(0, "F_");
    }
    if is_reserved(&n.to_ascii_lowercase()) { format!("{}_F", n) } else { n }
}

/// The record of packet or union `name` (`_T` after reserved names).
pub fn type_name(name: &str) -> String {
    let mut n = mixed_case(name);
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit()) {
        n.insert_str(0, "T_");
    }
    if is_reserved(&n.to_ascii_lowercase()) { format!("{}_T", n) } else { n }
}

/// The enumeration literal naming `arm` of union `union`.
pub fn arm_literal(union: &str, arm: &Arm) -> String {
    format!("{}_{}", type_name(union), variant_name(arm))
}

/// The package name: the `--package` option made an Ada identifier
/// (`packets` -> `Packets`). gnatchop names the files after it.
pub fn unit_name(opts: &GenOptions) -> String {
    let raw: String = opts.package.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let mut n = mixed_case(&raw);
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit()) {
        n.insert_str(0, "Pkg_");
    }
    n
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}_{}", if *signed { "Integer" } else { "Unsigned" }, storage_for(*width))
        }
        ValueType::Float { width: 32 } => "IEEE_Float_32".into(),
        ValueType::Float { .. } => "IEEE_Float_64".into(),
        ValueType::Mac => "Pb_Mac".into(),
        ValueType::Packet(n) | ValueType::Union(n) => type_name(n),
        ValueType::Str => "Pb_SU.Unbounded_String".into(),
    }
}

/// The container of `ty` elements: a runtime vector, or the `<T>_Array`
/// declared with the packets.
pub fn array_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed: false } if storage_for(*width) == 8 => "Pb_Bytes".into(),
        ValueType::Int { width, signed } => {
            format!("Pb_{}{}_Vectors.Vector", if *signed { "I" } else { "U" }, storage_for(*width))
        }
        ValueType::Float { width: 32 } => "Pb_F32_Vectors.Vector".into(),
        ValueType::Float { .. } => "Pb_F64_Vectors.Vector".into(),
        ValueType::Mac => "Pb_Mac_Vectors.Vector".into(),
        ValueType::Str => "Pb_Str_Vectors.Vector".into(),
        ValueType::Packet(n) | ValueType::Union(n) => format!("{}_Array", type_name(n)),
    }
}

/// A type as a record component names it: packets and unions qualified by
/// the package, since a component may share their name.
pub fn component_type(unit: &str, ty: &ValueType, array: bool) -> String {
    let t = if array { array_type(ty) } else { scalar_type(ty) };
    match ty {
        ValueType::Packet(_) | ValueType::Union(_) => format!("{}.{}", unit, t),
        _ => t,
    }
}

/// What a scalar component starts as (`:= 0`), if anything.
pub fn default_value(m: &Member) -> Option<String> {
    match (&m.array, &m.ty) {
        (Some(_), _) => None,
        (None, ValueType::Mac) => Some("(others => 0)".into()),
        (None, ValueType::Int { .. }) => Some(magic_literal(m).unwrap_or_else(|| "0".into())),
        (None, ValueType::Float { .. }) => Some("0.0".into()),
        _ => None,
    }
}

/// An Ada string literal: `"it""s"`, from the same text the other
/// backends quote with [`string_literal`].
pub fn ada_string(text: &str) -> String {
    let quoted = string_literal(text);
    let inner = &quoted[1..quoted.len() - 1];
    let mut out = String::from("\"");
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        let c = if c == '\\' { chars.next().unwrap_or('\\') } else { c };
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// `Pb_Byte_Array'(0 => 16#0D#, 1 => 16#0A#)`.
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().enumerate().map(|(i, b)| format!("{} => 16#{:02X}#", i, b)).collect();
    format!("Pb_Byte_Array'({})", items.join(", "))
}

/// `Pbp_<Name>`: a packet parameter in generated subprograms.
pub fn param_var(name: &str) -> String {
    format!("Pbp_{}", mixed_case_or(name))
}

/// `Pbc_<Name>`: the encode-time local of a calculated or derived member.
pub fn calc_var(name: &str) -> String {
    format!("Pbc_{}", mixed_case_or(name))
}

fn mixed_case_or(name: &str) -> String {
    let n = mixed_case(name);
    if n.is_empty() { "F".into() } else { n }
}

pub struct Ada;

impl Dialect for Ada {
    const TRUE: &'static str = "True";
    const FALSE: &'static str = "False";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("P.{}", ident(&member.name))
    }
}
