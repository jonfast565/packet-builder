//! Facts about source types: their value type, label and natural alignment.

use std::collections::HashMap;

use crate::ast::{TypeExpr, TypeNode};
use crate::ir::model::{Packet, ValueType};

pub(super) fn value_type(t: &TypeNode) -> ValueType {
    match t {
        TypeNode::Str | TypeNode::CStr | TypeNode::PrefixedStr { .. } => ValueType::Str,
        TypeNode::Float32 => ValueType::Float { width: 32 },
        TypeNode::Float64 => ValueType::Float { width: 64 },
        TypeNode::MacAddress => ValueType::Mac,
        TypeNode::Packet(n) => ValueType::Packet(n.clone()),
        other => {
            let (width, signed) = other.integer_info().expect("integer type");
            ValueType::Int { width, signed }
        }
    }
}

/// The type as written in source, for messages.
pub(super) fn type_label(t: &TypeNode) -> String {
    match t {
        TypeNode::Integer8 => "int8".into(),
        TypeNode::UnsignedInteger8 => "uint8".into(),
        TypeNode::Integer16 => "int16".into(),
        TypeNode::UnsignedInteger16 => "uint16".into(),
        TypeNode::Integer32 => "int32".into(),
        TypeNode::UnsignedInteger32 => "uint32".into(),
        TypeNode::Integer64 => "int64".into(),
        TypeNode::UnsignedInteger64 => "uint64".into(),
        TypeNode::Float32 => "float32".into(),
        TypeNode::Float64 => "float64".into(),
        TypeNode::MacAddress => "macaddress".into(),
        TypeNode::DateTime => "datetime".into(),
        TypeNode::Bytes => "bytes".into(),
        TypeNode::Bits { width, signed } => format!("{}{}", if *signed { "i" } else { "u" }, width),
        TypeNode::Packet(n) => n.clone(),
        TypeNode::Char => "char".into(),
        TypeNode::Str => "string".into(),
        TypeNode::CStr => "cstring".into(),
        TypeNode::PrefixedStr { prefix, .. } => format!("string({})", type_label(prefix)),
        TypeNode::Varint(k) => k.name().into(),
    }
}

/// Value type of a declared field: `char[n]` is a string.
pub(super) fn field_value_type(f: &TypeExpr) -> ValueType {
    if f.expr == TypeNode::Char && f.array.is_some() { ValueType::Str } else { value_type(&f.expr) }
}

/// Natural alignment in bytes of a type, as a C compiler would lay it out.
pub(super) fn natural_align(t: &TypeNode, done: &HashMap<String, Packet>) -> u64 {
    match t {
        TypeNode::Packet(n) => done.get(n).map(|p| p.alignment).unwrap_or(1),
        TypeNode::Bits { width, .. } => {
            let bytes = (*width / 8) as u64;
            if width % 8 == 0 && bytes.is_power_of_two() { bytes } else { 1 }
        }
        TypeNode::MacAddress | TypeNode::Bytes | TypeNode::Char | TypeNode::Str | TypeNode::CStr => 1,
        TypeNode::Varint(_) => 1,
        TypeNode::PrefixedStr { prefix, .. } => natural_align(prefix, done),
        other => other.bit_width().map(|b| (b / 8) as u64).unwrap_or(1),
    }
}
