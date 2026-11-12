//! Lua identifiers, field keys and the `Dialect` marker.

use crate::generators::common::Dialect;
use crate::generators::common::lua::LuaDialect;
use crate::ir::{Member, Packet};

pub use crate::generators::common::lua::index;

/// Marker for the dissector's Lua dialect of the shared expression scope
/// (`common::lua` spells its expressions).
pub struct WsLua;

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

impl Dialect for WsLua {
    const TRUE: &'static str = "true";
    const FALSE: &'static str = "false";

    fn field(_packet: &Packet, member: &Member) -> String {
        format!("p{}", index(&member.name))
    }
}

impl LuaDialect for WsLua {}
