//! The validated, language-independent packet model every backend consumes.

use std::collections::HashSet;

use super::expr::{Mark, TExpr};
use crate::ast::Endianness;
pub use crate::ast::Radix;

#[derive(Debug, Clone)]
pub struct Module {
    pub packets: Vec<Packet>,
    /// Standalone named constants, in source order.
    pub constants: Vec<Constant>,
    /// Categories of named constants, in source order.
    pub categories: Vec<Category>,
}

/// A named value from a `const` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Constant {
    pub name: String,
    /// Always an integer type.
    pub ty: ValueType,
    /// The value as 64-bit two's complement (a uint64 above i64::MAX is negative here).
    pub value: i64,
    /// How the value was written, so generated code can keep the spelling.
    pub radix: Radix,
    pub note: Option<String>,
}

impl Constant {
    /// The value as written for an unsigned or signed type, in its radix
    /// (hex for `0x`/`0b` sources, unless the value is negative).
    pub fn literal(&self) -> String {
        if self.ty.is_signed() {
            if self.value < 0 || self.radix == Radix::Dec {
                return self.value.to_string();
            }
            return format!("0x{:x}", self.value);
        }
        let v = self.value as u64;
        match self.radix {
            Radix::Dec => v.to_string(),
            Radix::Hex | Radix::Bin => format!("0x{:x}", v),
        }
    }
}

/// `const Name type { a = 1, ... }`: a group of related named constants.
#[derive(Debug, Clone, PartialEq)]
pub struct Category {
    pub name: String,
    pub ty: ValueType,
    pub members: Vec<Constant>,
}

impl ValueType {
    /// True if the 64-bit two's complement `value` is representable in this
    /// integer type (any bit pattern fits a 64-bit unsigned).
    pub fn holds(&self, value: i64) -> bool {
        match *self {
            ValueType::Int { width: 64, .. } => true,
            ValueType::Int { width, signed: true } => {
                let half = 1i64 << (width - 1);
                (-half..half).contains(&value)
            }
            ValueType::Int { width, signed: false } => (0..1i64 << width).contains(&value),
            _ => false,
        }
    }
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
    /// `assert` items, in source order (`Step::Assert` refers to them).
    pub asserts: Vec<Assertion>,
    /// Derived members, which decoding verifies after the last step.
    pub derived: Vec<usize>,
    /// Derived members whose value depends on the encoded bytes (`sizeof`,
    /// `offsetof`, checksums): encoding writes a placeholder and patches it
    /// after the last step, in this order.
    pub patches: Vec<usize>,
    /// Members only known after encoding the body: `patches` and the
    /// calculated members that depend on them.
    pub wire_dependent: Vec<usize>,
}

/// `assert cond "message"`.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub cond: TExpr,
    pub message: String,
}

impl Packet {
    /// True if decoding/encoding needs the packet's start position.
    pub fn uses_align(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, Step::Align { .. }))
    }

    /// Members that encoding evaluates up front (calculated members lengths
    /// need, and derived members that only depend on values), with their
    /// expressions, dependencies first.
    pub fn encode_calc_members(&self) -> impl Iterator<Item = (&Member, &TExpr)> {
        self.encode_calcs.iter().filter_map(|&c| {
            let m = &self.members[c];
            m.calc_expr().or(m.derived_expr()).map(|e| (m, e))
        })
    }

    /// True if `e` reads a member only known after encoding the body; such
    /// length checks and assertions are skipped when encoding.
    pub fn depends_on_wire(&self, e: &TExpr) -> bool {
        let mut deps = Vec::new();
        e.deps(&mut deps);
        deps.iter().any(|d| self.wire_dependent.contains(d))
    }

    /// The step that reads or writes stored member `member`.
    pub fn field_step(&self, member: usize) -> Option<usize> {
        self.steps.iter().position(|s| matches!(s, Step::Field { member: Some(m), .. } if *m == member))
    }

    /// The positions decoding (`encoding == false`) or encoding records: the
    /// marks read by verified or patched derived fields, and the position of
    /// each patched field.
    pub fn marks(&self, encoding: bool) -> Vec<Mark> {
        let mut out = Vec::new();
        let members: &[usize] = if encoding { &self.patches } else { &self.derived };
        for &m in members {
            let member = &self.members[m];
            if !encoding && member.lenient {
                continue;
            }
            if let Some(e) = member.derived_expr() {
                e.marks(&mut out);
            }
            if encoding && let Some(step) = self.field_step(m) {
                out.push(Mark::Before(step));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// True if decoding or encoding needs the packet's start position
    /// (`pb_start`): for alignment, or for a mark.
    pub fn needs_start(&self, encoding: bool) -> bool {
        self.uses_align() || self.marks(encoding).contains(&Mark::PacketStart)
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub ty: ValueType,
    pub array: Option<Count>,
    pub kind: MemberKind,
    /// `: Category`: the named constants this member's values come from.
    pub category: Option<String>,
    /// Declared checks on the value (`== v`, `in a..b`, `: Category strict`).
    pub checks: Vec<Check>,
    /// `lenient`: generated codecs do not enforce `checks`.
    pub lenient: bool,
}

/// A declared check on a member's value. Decoding fails with a `constraint`
/// error when `cond` is false (after reading the member); encoding fails
/// before writing it.
#[derive(Debug, Clone)]
pub struct Check {
    pub kind: CheckKind,
    pub cond: TExpr,
    /// What the value must be, for error messages ("`start` must be 0x2a").
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckKind {
    /// `== value`: a magic value; the member also defaults to it.
    Equals(i64),
    /// `in lo..hi`, inclusive.
    Range(i64, i64),
    /// `: Category strict`: one of the category's values.
    InCategory(String),
}

impl Member {
    /// The value of a `== value` check: what the member defaults to.
    pub fn magic(&self) -> Option<i64> {
        self.checks.iter().find_map(|c| match c.kind {
            CheckKind::Equals(v) => Some(v),
            _ => None,
        })
    }

    /// The checks generated codecs enforce (none for `lenient` members).
    pub fn enforced_checks(&self) -> &[Check] {
        if self.lenient { &[] } else { &self.checks }
    }

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

    /// The expression of a derived member (`length uint16 = len(payload)`).
    pub fn derived_expr(&self) -> Option<&TExpr> {
        match &self.kind {
            MemberKind::Derived(e) => Some(e),
            _ => None,
        }
    }

    pub fn is_derived(&self) -> bool {
        matches!(self.kind, MemberKind::Derived(_))
    }
}

#[derive(Debug, Clone)]
pub enum MemberKind {
    Stored,
    BitfieldPart,
    Calculated(TExpr),
    /// Stored on the wire, but computed when encoding and verified when
    /// decoding.
    Derived(TExpr),
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
    /// An integer container split into sub-fields; `name` is the container's.
    Bitfield { name: String, container: Codec, container_width: u32, parts: Vec<BitPart> },
    /// Evaluate a calculated member (decode only).
    Calc { member: usize },
    /// Skip (decode) or zero-fill (encode) to the next multiple of `bytes`
    /// bytes counted from the start of the packet.
    Align { bytes: u64 },
    /// Check `Packet::asserts[index]`, once its inputs are known.
    Assert { index: usize },
}

#[derive(Debug, Clone)]
pub struct BitPart {
    pub member: usize,
    pub shift: u32,
    pub width: u32,
    pub signed: bool,
}
