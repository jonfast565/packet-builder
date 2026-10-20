//! Lua identifiers, field keys and the `Dialect` marker.

use crate::generators::common::Dialect;
use crate::ir::{Member, Packet};

/// Marker for the Lua dialect of the shared expression scope.
pub struct Lua;

const KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "global", "goto", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// `.name`, or `["name"]` for a Lua keyword: indexing a table by `name`.
pub fn index(name: &str) -> String {
    if KEYWORDS.contains(&name) { format!("[\"{}\"]", name) } else { format!(".{}", name) }
}

/// `D.Name`: the dissect function of packet `name`.
pub fn dissect_fn(name: &str) -> String {
    format!("D{}", index(name))
}

/// The key of a member's field in the field table (`"Flap.channel"`).
pub fn field_key(owner: &str, member: &str) -> String {
    format!("\"{}.{}\"", owner, member)
}

/// The filter name of a field, after the protocol's (`flap.channel`).
pub fn field_abbrev(owner: &str, member: &str) -> String {
    format!("{}.{}", owner.to_ascii_lowercase(), member.to_ascii_lowercase())
}

impl Dialect for Lua {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p{}", index(&member.name))
    }
}
