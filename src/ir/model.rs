//! The validated, language-independent packet model every backend consumes.

use std::collections::HashSet;

use super::expr::TExpr;
use crate::models::parsing_models::Endianness;

#[derive(Debug, Clone)]
pub struct Module {
    pub packets: Vec<Packet>,
}

impl Module {
    /// Packets ordered so that every packet comes after the packets it
    /// contains (needed by languages that require declaration before use).
    pub fn in_dependency_order(&self) -> Vec<&Packet> {
        fn visit<'a>(m: &'a Module, p: &'a Packet, seen: &mut HashSet<String>, out: &mut Vec<&'a Packet>) {
            if !seen.insert(p.name.clone()) {
                return;
            }
            for member in &p.members {
                if let ValueType::Packet(n) = &member.ty
                    && let Some(dep) = m.packets.iter().find(|x| &x.name == n)
                {
                    visit(m, dep, seen, out);
                }
            }
            out.push(p);
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for p in &self.packets {
            visit(self, p, &mut seen, &mut out);
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub name: String,
    /// Struct members in declaration order (stored fields, bitfield members,
    /// calculated fields). Padding is not a member.
    pub members: Vec<Member>,
    /// Wire steps in order. Encoding walks the same list and skips `Calc`.
    pub steps: Vec<Step>,
    /// Calculated members that encoding needs (because a length depends on
    /// them), in an order where dependencies come first.
    pub encode_calcs: Vec<usize>,
    /// Smallest possible encoded size in bits.
    pub min_bits: u64,
    /// True if the last field consumes the rest of the input.
    pub open_ended: bool,
    /// Encoded size in bits when it does not depend on the data.
    pub fixed_bits: Option<u64>,
    /// Alignment in bytes of the packet when nested (from `packet P align N`).
    pub alignment: u64,
}

impl Packet {
    /// True if decoding/encoding needs the packet's start position.
    pub fn uses_align(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, Step::Align { .. }))
    }

    /// Calculated members that encoding evaluates up front, with their expressions.
    pub fn encode_calc_members(&self) -> impl Iterator<Item = (&Member, &TExpr)> {
        self.encode_calcs.iter().filter_map(|&c| {
            let m = &self.members[c];
            m.calc_expr().map(|e| (m, e))
        })
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub ty: ValueType,
    pub array: Option<Count>,
    pub kind: MemberKind,
}

impl Member {
    pub fn is_calculated(&self) -> bool {
        matches!(self.kind, MemberKind::Calculated(_))
    }

    /// The expression of a calculated member.
    pub fn calc_expr(&self) -> Option<&TExpr> {
        match &self.kind {
            MemberKind::Calculated(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MemberKind {
    Stored,
    BitfieldPart,
    Calculated(TExpr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValueType {
    /// Integer with a logical width of 1..=64 bits.
    Int { width: u32, signed: bool },
    /// IEEE float, 32 or 64 bits.
    Float { width: u32 },
    /// 6-byte hardware address.
    Mac,
    /// Another packet.
    Packet(String),
    /// Text (UTF-8).
    Str,
}

impl ValueType {
    /// Width of the native integer used to hold the value (8/16/32/64).
    pub fn storage_bits(&self) -> u32 {
        match self {
            ValueType::Int { width, .. } => storage_for(*width),
            ValueType::Float { width } => *width,
            ValueType::Mac => 48,
            ValueType::Packet(_) | ValueType::Str => 0,
        }
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, ValueType::Int { signed: true, .. })
    }

    /// Unsigned 8-bit values; arrays of them are represented as byte buffers.
    pub fn is_byte(&self) -> bool {
        matches!(self, ValueType::Int { width: 8, signed: false })
    }

    /// True if the logical width is narrower than the storage type, so values
    /// must be range-checked before encoding.
    pub fn needs_range_check(&self) -> bool {
        match self {
            ValueType::Int { width, .. } => *width != storage_for(*width),
            _ => false,
        }
    }
}

pub fn storage_for(width: u32) -> u32 {
    match width {
        0..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        _ => 64,
    }
}

#[derive(Debug, Clone)]
pub enum Count {
    Expr(TExpr),
    /// Repeat until the input is exhausted.
    Remaining,
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
    Packet(String),
    Str(StrMode),
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
}

impl Codec {
    pub fn bits(&self) -> u32 {
        match self {
            Codec::Bytes { nbytes, .. } => nbytes * 8,
            Codec::Bits { width } => *width,
            Codec::Float { width, .. } => *width,
            Codec::Mac => 48,
            Codec::Packet(_) | Codec::Str(_) => 0,
        }
    }

    /// Lower bound on the size of one element, used to reject element counts
    /// larger than the remaining input before allocating. Nested packets in
    /// arrays are at least one byte (enforced by the analysis).
    pub fn min_elem_bits(&self) -> u64 {
        match self {
            Codec::Packet(_) | Codec::Str(_) => 8,
            c => c.bits() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Step {
    /// A stored member, or padding when `member` is None.
    Field { member: Option<usize>, ty: ValueType, codec: Codec, array: Option<Count> },
    /// An integer container split into sub-fields.
    Bitfield { container: Codec, container_width: u32, parts: Vec<BitPart> },
    /// Evaluate a calculated member (decode only).
    Calc { member: usize },
    /// Skip (decode) or zero-fill (encode) to the next multiple of `bytes`
    /// bytes counted from the start of the packet.
    Align { bytes: u64 },
}

#[derive(Debug, Clone)]
pub struct BitPart {
    pub member: usize,
    pub shift: u32,
    pub width: u32,
    pub signed: bool,
}
