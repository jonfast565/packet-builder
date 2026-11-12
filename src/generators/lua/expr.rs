//! Lua expressions. `common::lua` implements `ExprLang` for every Lua
//! dialect (this backend's and the Wireshark dissector's), with
//! `store_value`; this module adds what only the codec needs.

use super::naming::{Lua, int_literal};
use crate::generators::common::Scope;
use crate::generators::common::lua::store_value;
use crate::ir::{Constant, PacketRef, Radix};

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Lua>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// A constant's value, keeping its spelling where Lua reads it as the
/// same integer.
pub fn const_literal(c: &Constant) -> String {
    let signed = c.ty.is_signed();
    if (c.value < 0 && !signed) || c.value == i64::MIN || c.radix == Radix::Dec {
        int_literal(c.value, signed)
    } else {
        c.literal()
    }
}
