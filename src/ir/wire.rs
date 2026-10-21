//! How fields travel on the wire: element codecs, counts and the steps a
//! packet is decoded and encoded in.

use super::expr::TExpr;
use super::model::{Arm, PacketRef, ValueType};
use crate::ast::Endianness;
use crate::ast::VarintKind;

#[derive(Debug, Clone)]
pub enum Count {
    Expr(TExpr),
    /// Repeat until the input is exhausted.
    Remaining,
    /// Repeat until the expression (over `last`, the element just read)
    /// holds, or the input ends; the element that ends it is kept.
    Until(TExpr),
    /// Bytes up to this sequence, which is consumed; `optional`: or up to
    /// the end of the input.
    Terminated {
        term: Vec<u8>,
        optional: bool,
    },
}

/// How a single element travels on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Codec {
    /// Byte aligned integer of `nbytes` bytes in the given byte order.
    Bytes {
        nbytes: u32,
        endian: Endianness,
    },
    /// Integer of `width` bits read MSB-first from the bit stream.
    Bits {
        width: u32,
    },
    Float {
        width: u32,
        endian: Endianness,
    },
    Mac,
    Packet(PacketRef),
    Str(StrMode),
    /// A variable-length integer.
    Varint(VarintKind),
}

/// How a string's length is determined. For `Padded` and `Exact` the byte
/// count is the step's `array` count.
#[derive(Debug, Clone, PartialEq)]
pub enum StrMode {
    /// `char[n]`: n bytes; the text ends at the first NUL, encoding pads with NULs.
    Padded,
    /// `string[n]` / `string[]`: exactly the given bytes.
    Exact,
    /// `string(uint8)`: a length prefix (written automatically), then the bytes.
    Prefixed { prefix: Box<Codec>, width: u32 },
    /// `cstring`: bytes up to a terminating NUL.
    CString,
    /// `string term 0x0d 0x0a`: bytes up to a terminator, which is consumed;
    /// `optional`: or up to the end of the input.
    Terminated { term: Vec<u8>, optional: bool },
}

impl Codec {
    pub fn bits(&self) -> u32 {
        match self {
            Codec::Bytes { nbytes, .. } => nbytes * 8,
            Codec::Bits { width } => *width,
            Codec::Float { width, .. } => *width,
            Codec::Mac => 48,
            Codec::Packet(_) | Codec::Str(_) | Codec::Varint(_) => 0,
        }
    }

    /// Lower bound on the size of one element, used to reject element counts
    /// larger than the remaining input before allocating. Nested packets in
    /// arrays are at least one byte (enforced by the analysis).
    pub fn min_elem_bits(&self) -> u64 {
        match self {
            Codec::Packet(_) | Codec::Str(_) | Codec::Varint(_) => 8,
            c => c.bits() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Step {
    /// A stored member, or padding when `member` is None.
    Field { member: Option<usize>, ty: ValueType, codec: Codec, array: Option<Count> },
    /// An integer container split into sub-fields; `name` is the container's.
    Bitfield { name: String, container: Codec, container_width: u32, parts: Vec<BitPart> },
    /// Evaluate a calculated member (decode only).
    Calc { member: usize },
    /// Skip (decode) or zero-fill (encode) to the next multiple of `bytes`
    /// bytes counted from the start of the packet.
    Align { bytes: u64 },
    /// Check `Packet::asserts[index]`, once its inputs are known.
    Assert { index: usize },
    /// A tagged union: `selector` picks one of `arms` (the member's union).
    Switch { member: usize, selector: TExpr, arms: Vec<Arm> },
    /// The next step occupies exactly `size` bytes (`size n` after a field).
    OpenWindow { size: TExpr, exact: bool },
    /// The end of the window opened by step `open`.
    CloseWindow { open: usize, exact: bool },
    /// The steps up to the matching `CloseGate` run only for protocol
    /// versions `from..=to`; `cond` tests that (`TExpr::Version`).
    OpenGate { from: u32, to: u32, cond: TExpr },
    /// The end of the gate opened by step `open`.
    CloseGate { open: usize },
    /// A packet stored elsewhere: `offset` bytes from the start of this
    /// packet, or of the whole input when `root`. Decoding reads it there
    /// and comes back; encoding places it there once the whole input is
    /// written (bytes already there must match).
    At { member: usize, target: PacketRef, offset: TExpr, root: bool },
}

#[derive(Debug, Clone)]
pub struct BitPart {
    pub member: usize,
    pub shift: u32,
    pub width: u32,
    pub signed: bool,
}
