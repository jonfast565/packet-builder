//! Type names and byte order keywords.

use crate::ast::{Endianness, TypeNode, VarintKind};

/// "unsigned   char" -> "unsigned char"
pub(super) fn normalize_type(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The type named `type_name`; `word` is the file's word size in bits (for `word`, `dword`, ...).
pub(super) fn type_from_name(type_name: &str, word: u32) -> TypeNode {
    let sized = |bits: u32| match bits {
        8 => TypeNode::UnsignedInteger8,
        16 => TypeNode::UnsignedInteger16,
        32 => TypeNode::UnsignedInteger32,
        _ => TypeNode::UnsignedInteger64,
    };
    match normalize_type(type_name).as_str() {
        // C-style and assembly-style aliases
        "char" => TypeNode::Char,
        "uchar" | "unsigned char" | "byte" => TypeNode::UnsignedInteger8,
        "short" => TypeNode::Integer16,
        "ushort" | "unsigned short" => TypeNode::UnsignedInteger16,
        "int" => TypeNode::Integer32,
        "uint" | "unsigned int" => TypeNode::UnsignedInteger32,
        "halfword" | "half word" => sized(word / 2),
        "word" => sized(word),
        "dword" | "doubleword" | "double word" => sized(word * 2),
        "qword" | "quadword" | "quad word" => sized(word * 4),
        "string" => TypeNode::Str,
        "cstring" => TypeNode::CStr,
        "int8" => TypeNode::Integer8,
        "uint8" => TypeNode::UnsignedInteger8,
        "int16" => TypeNode::Integer16,
        "uint16" => TypeNode::UnsignedInteger16,
        "int32" => TypeNode::Integer32,
        "uint32" => TypeNode::UnsignedInteger32,
        "int64" => TypeNode::Integer64,
        "uint64" => TypeNode::UnsignedInteger64,
        "float32" => TypeNode::Float32,
        "float64" => TypeNode::Float64,
        "macaddress" => TypeNode::MacAddress,
        "datetime" => TypeNode::DateTime,
        "bytes" => TypeNode::Bytes,
        "uleb128" | "varint" => TypeNode::Varint(VarintKind::Uleb128),
        "sleb128" => TypeNode::Varint(VarintKind::Sleb128),
        "zigzag" => TypeNode::Varint(VarintKind::Zigzag),
        "vlq" => TypeNode::Varint(VarintKind::Vlq),
        "quic_varint" => TypeNode::Varint(VarintKind::Quic),
        other => {
            // bit_type: validated by check_literals
            let signed = other.starts_with('i');
            let width = other[1..].parse::<u32>().expect("bit width validated earlier");
            TypeNode::Bits { width, signed }
        }
    }
}

pub(super) fn to_endianness(s: &str) -> Option<Endianness> {
    match s {
        "le" => Some(Endianness::Le),
        "be" => Some(Endianness::Be),
        _ => None,
    }
}
