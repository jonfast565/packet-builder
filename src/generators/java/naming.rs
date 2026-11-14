//! Java identifiers, types and literals.

use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, GenOptions, pascal_case};
use crate::ir::{Arm, Member, Packet, ValueType, storage_for};

/// Java keywords and literals, and the restricted identifiers.
const KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
    "var",
    "record",
    "yield",
    "sealed",
    "permits",
    "when",
    "_",
];

/// Class names the generated file uses unqualified: `java.lang` types, the
/// `java` package prefix, and the runtime's classes. A packet, union, arm or
/// category with one of these names gets a `_` appended.
const TAKEN: &[&str] = &[
    "java",
    "javax",
    "Boolean",
    "Byte",
    "Character",
    "CharSequence",
    "Class",
    "Comparable",
    "Constants",
    "Deprecated",
    "Double",
    "Enum",
    "Error",
    "Exception",
    "Float",
    "FunctionalInterface",
    "Integer",
    "Iterable",
    "Long",
    "Math",
    "Number",
    "Object",
    "Override",
    "Pb",
    "PbErrorKind",
    "PbException",
    "PbReader",
    "PbStatus",
    "PbTrace",
    "PbWriter",
    "Record",
    "Runnable",
    "RuntimeException",
    "SafeVarargs",
    "Short",
    "String",
    "StringBuilder",
    "SuppressWarnings",
    "System",
    "Thread",
    "Void",
];

/// The class that holds everything in a generated file (`Packets`); the
/// file must be named after it.
pub fn outer_class(opts: &GenOptions) -> String {
    pascal_case(&opts.package)
}

thread_local! {
    /// The outer class of the file being generated, which arm classes
    /// avoid; set by [`set_outer`] for expressions (`ExprLang::holds`).
    static OUTER: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

pub fn set_outer(outer: &str) {
    OUTER.with(|o| *o.borrow_mut() = outer.to_string());
}

pub fn current_outer() -> String {
    OUTER.with(|o| o.borrow().clone())
}

/// The nested class of a packet, union or category.
pub fn class_name(name: &str) -> String {
    if KEYWORDS.contains(&name) || TAKEN.contains(&name) { format!("{}_", name) } else { name.to_string() }
}

/// The class of an arm of union `union` (nested in it, so it must differ
/// from it, and from the outer class its packet types are qualified with).
pub fn arm_class(union: &str, arm: &Arm, outer: &str) -> String {
    let v = variant_name(arm);
    if v == union || v == outer || v == class_name(union) || TAKEN.contains(&v.as_str()) {
        format!("{}_", v)
    } else {
        v
    }
}

/// Java field name for a member: camelCase, keywords escaped.
pub fn field_name(name: &str) -> String {
    let n = pascal_case(name);
    let mut chars = n.chars();
    let mut out: String = chars.next().map(|c| c.to_lowercase().collect()).unwrap_or_default();
    out.push_str(chars.as_str());
    if KEYWORDS.contains(&out.as_str()) { format!("{}_", out) } else { out }
}

/// The Java type of a value. Unsigned values take the next wider signed
/// type (`uint8` is an `int`), except `uint64`, whose `long` holds the bit
/// pattern.
pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed: true } => match storage_for(*width) {
            8 => "byte",
            16 => "short",
            32 => "int",
            _ => "long",
        }
        .to_string(),
        ValueType::Int { width, signed: false } => if *width <= 16 { "int" } else { "long" }.to_string(),
        ValueType::Float { width: 32 } => "float".into(),
        ValueType::Float { .. } => "double".into(),
        ValueType::Mac => "byte[]".into(),
        ValueType::Packet(n) | ValueType::Union(n) => class_name(n),
        ValueType::Str => "String".into(),
    }
}

/// True when the Java type of `ty` holds values its width does not allow,
/// so they are range-checked before encoding.
pub fn needs_check(ty: &ValueType) -> bool {
    match ty {
        ValueType::Int { width, signed: false } => *width < 64,
        ValueType::Int { width, signed: true } => *width != storage_for(*width),
        _ => false,
    }
}

/// A byte buffer's type: an array, or (zero-copy) a read-only view of the input.
pub fn bytes_type(zero_copy: bool) -> &'static str {
    if zero_copy { "java.nio.ByteBuffer" } else { "byte[]" }
}

/// The type of a member: arrays of `uint8` are byte buffers.
pub fn member_type(m: &Member, zero_copy: bool) -> String {
    match m.array {
        Some(_) if m.ty.is_byte() => bytes_type(zero_copy).into(),
        Some(_) => format!("{}[]", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

/// `new T[n]` for element type `elem` (`new byte[n][]` for arrays of arrays).
pub fn new_array(elem: &str, n: &str) -> String {
    match elem.strip_suffix("[]") {
        Some(inner) => format!("new {}[{}][]", inner, n),
        None => format!("new {}[{}]", elem, n),
    }
}

/// An integer literal of the Java type of `ty` holding `v` (two's
/// complement): `long` literals get an `L`, and unsigned values above
/// `Long.MAX_VALUE` are written as their bit pattern in hex.
pub fn int_literal(ty: &ValueType, v: i64, spelled: &str) -> String {
    if scalar_type(ty) != "long" {
        return spelled.to_string();
    }
    if !ty.is_signed() && v < 0 { format!("0x{:x}L", v as u64) } else { format!("{}L", spelled) }
}

pub fn default_value(m: &Member, zero_copy: bool) -> Option<String> {
    match (&m.array, &m.ty) {
        (Some(_), ty) if ty.is_byte() => {
            Some(if zero_copy { "java.nio.ByteBuffer.allocate(0)".into() } else { "new byte[0]".into() })
        }
        (Some(_), ty) => Some(new_array(&scalar_type(ty), "0")),
        (None, ValueType::Mac) => Some("new byte[6]".into()),
        (None, ValueType::Packet(n)) => Some(format!("new {}()", class_name(n))),
        (None, ValueType::Union(n)) => Some(format!("{}.pbDefault()", class_name(n))),
        (None, ValueType::Str) => Some("\"\"".into()),
        (None, ty) => m.magic().map(|v| int_literal(ty, v, &v.to_string())),
    }
}

/// Text for a `/** ... */` comment: no `*/`, HTML escaped, and no
/// backslashes (javac reads `\u` escapes even in comments).
pub fn doc_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('@', "&#64;")
        .replace('\\', "&#92;")
        .replace("*/", "*&#47;")
}

pub struct Java;

impl Dialect for Java {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", field_name(&member.name))
    }
}
