//! C# identifiers and types.

use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, GenOptions, magic_literal, pascal_case};
use crate::ir::{Arm, Member, Packet, ValueType, storage_for};

/// The nested class for an arm of union `union`: it must differ from its
/// `Value` property and from the union class.
pub fn arm_class(union: &str, arm: &Arm) -> String {
    let v = variant_name(arm);
    if v == "Value" || v == union { format!("{}_", v) } else { v }
}

/// C# property name for a member of packet `packet`.
pub fn prop_name(packet: &str, name: &str) -> String {
    let n = pascal_case(name);
    match n.as_str() {
        "Decode" | "DecodeFrom" | "Encode" | "EncodeTo" | "GetType" | "ToString" | "Equals" | "GetHashCode" => {
            format!("{}_", n)
        }
        _ if n == packet => format!("{}_", n),
        _ => n,
    }
}

pub fn namespace(opts: &GenOptions) -> String {
    pascal_case(&opts.package)
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => match (storage_for(*width), signed) {
            (8, false) => "byte",
            (8, true) => "sbyte",
            (16, false) => "ushort",
            (16, true) => "short",
            (32, false) => "uint",
            (32, true) => "int",
            (_, false) => "ulong",
            (_, true) => "long",
        }
        .to_string(),
        ValueType::Float { width: 32 } => "float".into(),
        ValueType::Float { .. } => "double".into(),
        ValueType::Mac => "byte[]".into(),
        ValueType::Packet(n) | ValueType::Union(n) => n.clone(),
        ValueType::Str => "string".into(),
    }
}

pub fn member_type(m: &Member) -> String {
    match m.array {
        Some(_) => format!("{}[]", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

pub fn default_value(m: &Member) -> Option<String> {
    match (&m.array, &m.ty) {
        (Some(_), ty) => Some(format!("Array.Empty<{}>()", scalar_type(ty))),
        (None, ValueType::Mac) => Some("new byte[6]".into()),
        (None, ValueType::Packet(n)) => Some(format!("new {}()", n)),
        (None, ValueType::Union(n)) => Some(format!("{}.PbDefault()", n)),
        (None, ValueType::Str) => Some("\"\"".into()),
        _ => magic_literal(m),
    }
}

pub struct CSharp;

impl Dialect for CSharp {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(packet: &Packet, member: &Member) -> String {
        format!("p.{}", prop_name(&packet.name, &member.name))
    }
}
