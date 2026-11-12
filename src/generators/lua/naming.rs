//! Lua identifiers, default values and the `Dialect` marker.

use crate::generators::common::Dialect;
use crate::generators::common::lua::{LuaDialect, index, is_keyword};
use crate::ir::{Member, Packet, ValueType};

/// Marker for the Lua dialect of the shared expression scope; its
/// expressions are spelled by `common::lua`, like the dissector's.
pub struct Lua;

impl Dialect for Lua {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p{}", index(&member.name))
    }
}

impl LuaDialect for Lua {
    const EXACT_U64: bool = true;
}

/// The class of packet or union `name` in the module table (`M.Name`).
pub fn class(name: &str) -> String {
    format!("M{}", index(name))
}

/// `name = ` in a table constructor (`["end"] = ` for a keyword).
pub fn key(name: &str) -> String {
    if is_keyword(name) { format!("[\"{}\"] = ", name) } else { format!("{} = ", name) }
}

/// An integer literal for a 64-bit two's complement value: uint64 values
/// above i64::MAX as (wrapping) hex, since decimal ones would be floats.
pub fn int_literal(v: i64, signed: bool) -> String {
    if v == i64::MIN && signed {
        "math.mininteger".into()
    } else if v < 0 && !signed {
        format!("0x{:x}", v as u64)
    } else {
        v.to_string()
    }
}

/// The value member `m` starts with.
pub fn default_value(m: &Member) -> String {
    match (&m.array, &m.ty) {
        (Some(_), ty) if ty.is_byte() => "\"\"".into(),
        (Some(_), _) => "{}".into(),
        (None, ValueType::Int { signed, .. }) => {
            m.magic().map(|v| int_literal(v, *signed)).unwrap_or_else(|| "0".into())
        }
        (None, ValueType::Float { .. }) => "0.0".into(),
        (None, ValueType::Mac) => "\"\\0\\0\\0\\0\\0\\0\"".into(),
        (None, ValueType::Packet(n)) => format!("{}.new()", class(n)),
        (None, ValueType::Union(n)) => format!("{}.default()", class(n)),
        (None, ValueType::Str) => "\"\"".into(),
    }
}
