//! Fortran identifiers, kinds and literals.

use crate::generators::common::{Dialect, GenOptions, string_literal};
use crate::ir::{Arm, Member, Packet, Union, ValueType, storage_for};

/// Names a derived type or constant must not take (compared in lower
/// case, since Fortran ignores case): a module-level name hides the
/// intrinsic or statement keyword of the same name in every procedure of
/// the module, and the runtime and generated code use these.
const RESERVED: &[&str] = &[
    // types, kinds and intrinsic modules
    "integer",
    "real",
    "complex",
    "logical",
    "character",
    "doubleprecision",
    "int8",
    "int16",
    "int32",
    "int64",
    "real32",
    "real64",
    "iso_fortran_env",
    "ieee_arithmetic",
    "ieee_is_nan",
    "ieee_value",
    "ieee_quiet_nan",
    "ieee_positive_inf",
    "ieee_negative_inf",
    "packets",
    // intrinsic procedures the code uses
    "int",
    "iand",
    "ior",
    "ieor",
    "not",
    "ishft",
    "shiftr",
    "shifta",
    "shiftl",
    "maskr",
    "maskl",
    "ibits",
    "btest",
    "ibset",
    "ibclr",
    "abs",
    "mod",
    "max",
    "min",
    "merge",
    "size",
    "len",
    "allocated",
    "huge",
    "achar",
    "char",
    "ichar",
    "iachar",
    "trim",
    "adjustl",
    "all",
    "any",
    "sqrt",
    "transfer",
    "lbound",
    "ubound",
    "present",
    "move_alloc",
    "kind",
    "selected_int_kind",
    "null",
    "associated",
    // statements and attributes
    "allocate",
    "deallocate",
    "end",
    "type",
    "contains",
    "procedure",
    "module",
    "function",
    "subroutine",
    "interface",
    "use",
    "implicit",
    "none",
    "if",
    "then",
    "else",
    "do",
    "while",
    "select",
    "case",
    "default",
    "call",
    "data",
    "format",
    "program",
    "block",
    "associate",
    "class",
    "public",
    "private",
    "sequence",
    "extends",
    "abstract",
    "operator",
    "assignment",
    "result",
    "recursive",
    "pure",
    "elemental",
    "impure",
    "intent",
    "in",
    "out",
    "inout",
    "optional",
    "value",
    "save",
    "parameter",
    "dimension",
    "allocatable",
    "pointer",
    "target",
    "external",
    "intrinsic",
    "go",
    "goto",
    "continue",
    "cycle",
    "exit",
    "return",
    "stop",
    "where",
    "forall",
    "read",
    "write",
    "print",
    "open",
    "close",
    "entry",
    "equivalence",
    "common",
    "namelist",
    "include",
    "enum",
    "enumerator",
    "import",
    "protected",
    "volatile",
    "asynchronous",
    "bind",
    "final",
    "generic",
    "nopass",
    "pass",
    "deferred",
    "non_overridable",
    "critical",
    "sync",
    "error",
    "lock",
    "unlock",
    "concurrent",
    "codimension",
    "contiguous",
    "submodule",
];

/// Fortran names are at most 63 characters.
const MAX_NAME: usize = 63;

/// True if `name` may not name a module-level entity.
pub fn reserved(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    RESERVED.contains(&lower.as_str()) || lower.starts_with("pb")
}

/// A name cut to the length Fortran allows, keeping it unique with a hash
/// of the whole name.
fn fit(name: String, room: usize) -> String {
    if name.len() <= room {
        return name;
    }
    let hash = name.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    format!("{}_{:x}", &name[..room - 9], hash)
}

/// The derived type of packet or union `name`: the name itself, with `_`
/// after names that would hide an intrinsic or keyword. Short enough for
/// the longest procedure name built on it (`<type>_try_decode`).
pub fn type_name(name: &str) -> String {
    let n = if reserved(name) { format!("{}_", name) } else { name.to_string() };
    fit(n, MAX_NAME - "_try_decode".len())
}

/// The module name: the package, made an identifier (the file is
/// `<package>.f90`).
pub fn module_name(opts: &GenOptions) -> String {
    let mut n: String = opts.package.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if n.is_empty() || !n.starts_with(|c: char| c.is_ascii_alphabetic()) {
        n.insert(0, 'm');
    }
    fit(n, MAX_NAME)
}

/// A component (member or union arm) name; components live in their
/// type's own namespace, so only the length matters.
pub fn component(name: &str) -> String {
    fit(name.to_string(), MAX_NAME - 4)
}

/// The component holding union arm `arm`.
pub fn arm_component(arm: &Arm) -> String {
    component(&arm.name)
}

/// The named constant for the tag of union arm `index` (from 0).
pub fn arm_tag(u: &Union, arm: &Arm) -> String {
    fit(format!("{}_{}", type_name(&u.name), arm.name), MAX_NAME)
}

/// The integer kind that stores a value of `width` bits: unsigned values
/// need a wider kind (Fortran has no unsigned integers), except 64-bit
/// ones, which keep their bit pattern in an int64.
pub fn int_kind(width: u32, signed: bool) -> &'static str {
    let bits = if signed || width >= 64 {
        storage_for(width)
    } else {
        match width {
            0..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            _ => 64,
        }
    };
    match bits {
        8 => "int8",
        16 => "int16",
        32 => "int32",
        _ => "int64",
    }
}

/// The bits of the storage kind `int_kind` picks.
pub fn kind_bits(kind: &str) -> u32 {
    match kind {
        "int8" => 8,
        "int16" => 16,
        "int32" => 32,
        _ => 64,
    }
}

pub fn real_kind(width: u32) -> &'static str {
    if width == 32 { "real32" } else { "real64" }
}

/// The declared type of a single value of `ty`.
pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => format!("integer({})", int_kind(*width, *signed)),
        ValueType::Float { width } => format!("real({})", real_kind(*width)),
        ValueType::Mac => "integer(int8)".into(),
        ValueType::Packet(n) | ValueType::Union(n) => format!("type({})", type_name(n)),
        ValueType::Str => "character(len=:)".into(),
    }
}

/// The element type of an array of `ty`: bytes keep their bit pattern in
/// int8, hardware addresses are `pb_mac`.
pub fn elem_type(ty: &ValueType) -> String {
    match ty {
        _ if ty.is_byte() => "integer(int8)".into(),
        ValueType::Mac => "type(pb_mac)".into(),
        ValueType::Str => "type(pb_string)".into(),
        _ => scalar_type(ty),
    }
}

/// The declaration of member `m` (`integer(int16) :: len = 0_int16`).
pub fn member_decl(m: &Member, at: bool) -> String {
    let name = component(&m.name);
    if m.array.is_some() {
        return format!("{}, allocatable :: {}(:)", elem_type(&m.ty), name);
    }
    match &m.ty {
        ValueType::Str => format!("character(len=:), allocatable :: {}", name),
        ValueType::Mac => format!("integer(int8) :: {}(6) = 0_int8", name),
        ValueType::Packet(n) if at => format!("type({}), allocatable :: {}", type_name(n), name),
        ValueType::Packet(_) | ValueType::Union(_) => format!("{} :: {}", scalar_type(&m.ty), name),
        ValueType::Int { width, signed } => {
            let kind = int_kind(*width, *signed);
            let v = m.magic().unwrap_or(0);
            format!("{} :: {} = {}", scalar_type(&m.ty), name, int_const(magic_value(v, *width, *signed), kind))
        }
        ValueType::Float { width } => {
            let v = m.magic().unwrap_or(0);
            format!("{} :: {} = {}.0_{}", scalar_type(&m.ty), name, v, real_kind(*width))
        }
    }
}

/// A constant of integer kind `kind` (`v` must fit it).
pub fn int_const(v: i64, kind: &str) -> String {
    let bits = kind_bits(kind);
    let min = if bits == 64 { i64::MIN } else { -(1i64 << (bits - 1)) };
    if v == min {
        format!("(-{}_{} - 1_{})", -(min + 1), kind, kind)
    } else if v < 0 {
        format!("(-{}_{})", -v, kind)
    } else {
        format!("{}_{}", v, kind)
    }
}

/// The stored form of the `== value` of an integer member: unsigned
/// 64-bit values keep their bit pattern, others their value.
fn magic_value(v: i64, width: u32, signed: bool) -> i64 {
    if signed || width >= 64 { v } else { v & ((1i64 << width) - 1) }
}

/// A Fortran string literal (`'it''s'`), from the same text the other
/// backends quote with [`string_literal`].
pub fn f_string(text: &str) -> String {
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

/// A text literal taken as it is (JSON keys): quotes doubled.
pub fn raw_string(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// `[13_int8, 10_int8]`: an array of bytes (as int8 bit patterns).
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|&b| int_const(b as i8 as i64, "int8")).collect();
    format!("[{}]", items.join(", "))
}

pub struct Fortran;

impl Dialect for Fortran {
    const TRUE: &'static str = ".true.";
    const FALSE: &'static str = ".false.";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("pbv%{}", component(&member.name))
    }
}
