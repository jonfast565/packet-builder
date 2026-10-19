//! What every backend must say about its language to share the generic
//! expression scope.

use std::marker::PhantomData;

use super::expr::{ExprLang, Mode, emit_expr};
use crate::ir::{Member, Packet, TExpr};
use crate::models::parsing_models::Endianness;

/// Spelling rules of a target language. Each backend has one zero-sized
/// marker type implementing this; [`Scope`] is generic over it.
pub trait Dialect {
    /// Boolean literals of the language (`true`/`false`, `True`/`False`, `1`/`0`).
    const TRUE: &'static str;
    const FALSE: &'static str;

    /// Expression naming member `member` of the value being coded, e.g. `p.len`.
    fn field(packet: &Packet, member: &Member) -> String;

    fn flag(value: bool) -> &'static str {
        if value { Self::TRUE } else { Self::FALSE }
    }

    /// The `little` argument passed to the runtime's integer readers and writers.
    fn little(e: &Endianness) -> &'static str {
        Self::flag(*e == Endianness::Le)
    }
}

/// The context an expression is emitted in: one packet, while decoding or
/// encoding. Backends implement [`ExprLang`] for `Scope<'_, TheirDialect>`.
pub struct Scope<'a, D> {
    pub packet: &'a Packet,
    pub mode: Mode,
    dialect: PhantomData<D>,
}

impl<'a, D: Dialect> Scope<'a, D> {
    pub fn new(packet: &'a Packet, mode: Mode) -> Self {
        Scope { packet, mode, dialect: PhantomData }
    }

    pub fn member(&self, member: usize) -> &'a Member {
        &self.packet.members[member]
    }

    /// Where an expression reads `member`: calculated members are locals
    /// (`pbc_<name>`) while encoding, since they are not stored.
    pub fn place(&self, member: usize) -> String {
        let m = self.member(member);
        if self.mode == Mode::Encode && m.is_calculated() {
            format!("pbc_{}", m.name)
        } else {
            D::field(self.packet, m)
        }
    }

    /// The stored field of `m` (never the encode-time local).
    pub fn field(&self, m: &Member) -> String {
        D::field(self.packet, m)
    }

    pub fn expr(&self, e: &TExpr) -> String
    where
        Self: ExprLang,
    {
        emit_expr(self, e)
    }
}
