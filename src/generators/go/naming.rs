//! Go identifiers and types.

use crate::generators::common::{Dialect, pascal_case};
use crate::ir::{Member, Packet, ValueType, storage_for};

/// Exported Go field name for a member.
pub fn field_name(name: &str) -> String {
    let n = pascal_case(name);
    match n.as_str() {
        "DecodeFrom" | "Encode" | "EncodeTo" => format!("{}_", n),
        _ => n,
    }
}

pub fn scalar_type(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("{}int{}", if *signed { "" } else { "u" }, storage_for(*width))
        }
        ValueType::Float { width } => format!("float{}", width),
        ValueType::Mac => "[6]byte".into(),
        ValueType::Packet(n) => n.clone(),
        ValueType::Str => "string".into(),
    }
}

pub fn member_type(m: &Member) -> String {
    match m.array {
        Some(_) => format!("[]{}", scalar_type(&m.ty)),
        None => scalar_type(&m.ty),
    }
}

pub struct Go;

impl Dialect for Go {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p.{}", field_name(&member.name))
    }
}
