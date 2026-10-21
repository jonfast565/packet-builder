//! The parse tree produced by [`crate::parser`] and consumed by [`crate::ir::analyze`].

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endianness {
    Le,
    Be,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprNode {
    NoExpr,
    UnsignedInteger64Value(u64),
    Float64Value(f64),
    StringValue(String),

    // identifiers and optional index expression (e.g., foo[expr])
    ValueReference(String, Option<Box<ExprNode>>),

    // `Category.member`: a named constant from a category
    QualifiedReference(String, String),

    // function call: name(args...)
    Call(String, Vec<ExprNode>),

    // a function over fields: len(x), sizeof(a..b), offsetof(f), crc32(self)
    RangeCall(String, FieldRange),

    GuardExpression(Box<ExprNode>, Box<ExprNode>, Box<ExprNode>), // when cond then a otherwise b

    // aggregates: sumof foo / productof bar
    AggregateSum(String),
    AggregateProduct(String),

    // arithmetic
    Plus(Box<ExprNode>, Box<ExprNode>),
    Minus(Box<ExprNode>, Box<ExprNode>),
    Mult(Box<ExprNode>, Box<ExprNode>),
    Div(Box<ExprNode>, Box<ExprNode>),
    Pow(Box<ExprNode>, Box<ExprNode>),
    Mod(Box<ExprNode>, Box<ExprNode>),

    // bitwise
    Shl(Box<ExprNode>, Box<ExprNode>),
    Shr(Box<ExprNode>, Box<ExprNode>),
    BitAnd(Box<ExprNode>, Box<ExprNode>),
    BitOr(Box<ExprNode>, Box<ExprNode>),
    BitXor(Box<ExprNode>, Box<ExprNode>),

    // unary: -x, ~x, not x
    Neg(Box<ExprNode>),
    BitNot(Box<ExprNode>),
    Not(Box<ExprNode>),

    // comparisons
    Gt(Box<ExprNode>, Box<ExprNode>),
    Gte(Box<ExprNode>, Box<ExprNode>),
    Lt(Box<ExprNode>, Box<ExprNode>),
    Lte(Box<ExprNode>, Box<ExprNode>),
    Equals(Box<ExprNode>, Box<ExprNode>),
    NotEquals(Box<ExprNode>, Box<ExprNode>),

    // boolean
    And(Box<ExprNode>, Box<ExprNode>),
    Or(Box<ExprNode>, Box<ExprNode>),
}

/// The argument of a function over fields.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldRange {
    /// `self`: the whole packet.
    Whole,
    /// `a` or `a..b` (inclusive).
    Fields(String, Option<String>),
}

/// `@2..`, `@..3`, `@2..3` or `@2` (the same as `@2..`) before a
/// declaration: the protocol versions it applies to, inclusive. An open end
/// is filled in by analysis (from 1, or until the next re-declaration or the
/// latest version).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    pub from: Option<u32>,
    pub to: Option<u32>,
    pub span: Span,
}

/// Source location of a declaration (byte offsets into the input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A field's element type, as written in the source.
#[derive(Debug, Clone, PartialEq)]
pub enum TypeNode {
    Integer8,
    UnsignedInteger8,
    Integer16,
    UnsignedInteger16,
    Integer32,
    UnsignedInteger32,
    Integer64,
    UnsignedInteger64,
    Float32,
    Float64,
    MacAddress,
    DateTime,
    Bytes, // opaque blob; element type is a byte
    /// `char`: one 8-bit character. `char[n]` is a fixed-size, NUL-padded string.
    Char,
    /// `string[n]` (exactly n bytes) or `string` / `string[]` (rest of input).
    Str,
    /// NUL-terminated string.
    CStr,
    /// `string(uint8)`: a string preceded by its length in bytes.
    PrefixedStr {
        prefix: Box<TypeNode>,
        endianness: Option<Endianness>,
    },
    /// Arbitrary-width integer: `u3`, `i12`, ...
    Bits {
        width: u32,
        signed: bool,
    },
    /// Reference to another packet by name.
    Packet(String),
    /// A variable-length integer.
    Varint(VarintKind),
}

/// Variable-length integer encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintKind {
    /// Unsigned LEB128 (protobuf `varint`): 7 bits per byte, least significant first.
    Uleb128,
    /// Signed LEB128 (DWARF, WebAssembly).
    Sleb128,
    /// Protobuf `sint`: zigzag-mapped, then unsigned LEB128.
    Zigzag,
    /// 7 bits per byte, most significant first (MIDI, ASN.1 tags).
    Vlq,
    /// QUIC (RFC 9000): a 2-bit length (1, 2, 4 or 8 bytes) and 6 to 62 bits.
    Quic,
    /// One byte below 0x80, otherwise two big-endian bytes with the top bit
    /// set: 15 bits (AOL's FDO argument lengths).
    Varint15,
}

impl VarintKind {
    pub fn signed(self) -> bool {
        matches!(self, VarintKind::Sleb128 | VarintKind::Zigzag)
    }

    /// The number the runtimes use for this encoding.
    pub fn id(self) -> u32 {
        self as u32
    }

    pub fn name(self) -> &'static str {
        match self {
            VarintKind::Uleb128 => "uleb128",
            VarintKind::Sleb128 => "sleb128",
            VarintKind::Zigzag => "zigzag",
            VarintKind::Vlq => "vlq",
            VarintKind::Quic => "quic_varint",
            VarintKind::Varint15 => "varint15",
        }
    }
}

/// How a string's characters become bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextEncoding {
    #[default]
    Utf8,
    /// 7-bit ASCII; other characters are errors.
    Ascii,
    /// ISO-8859-1: each byte is the character with that code.
    Latin1,
    Utf16Le,
    Utf16Be,
}

impl TextEncoding {
    pub fn from_name(name: &str) -> Option<TextEncoding> {
        Some(match name {
            "utf8" => TextEncoding::Utf8,
            "ascii" => TextEncoding::Ascii,
            "latin1" => TextEncoding::Latin1,
            "utf16le" => TextEncoding::Utf16Le,
            "utf16be" => TextEncoding::Utf16Be,
            _ => return None,
        })
    }

    /// The number the runtimes use for this encoding.
    pub fn id(self) -> u32 {
        self as u32
    }

    pub fn name(self) -> &'static str {
        match self {
            TextEncoding::Utf8 => "utf8",
            TextEncoding::Ascii => "ascii",
            TextEncoding::Latin1 => "latin1",
            TextEncoding::Utf16Le => "utf16le",
            TextEncoding::Utf16Be => "utf16be",
        }
    }

    pub fn is_utf16(self) -> bool {
        matches!(self, TextEncoding::Utf16Le | TextEncoding::Utf16Be)
    }
}

/// Array length specifier on a declaration.
#[derive(Debug, Clone, PartialEq)]
pub enum ArrayLength {
    /// `[expr]`
    Expr(ExprNode),
    /// `[]` (or a bare `bytes`): everything up to the end of the input
    Remaining,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeExpr {
    pub id: String,
    pub expr: TypeNode,
    pub array: Option<ArrayLength>,
    pub endianness: Option<Endianness>,
    /// `align N`: pad to a multiple of N bytes (from the packet start) first.
    pub align: Option<u64>,
    /// `: Category`: the named constants this field's values come from.
    pub category: Option<(String, Span)>,
    /// `= expr`: a derived field, computed when encoding.
    pub derive: Option<ExprNode>,
    /// `placeholder value` after a derivation: a stand-in the field may hold
    /// instead of the computed value.
    pub placeholder: Option<ExprNode>,
    /// `size n [exact]`: the field occupies exactly n bytes.
    pub window: Option<WindowExpr>,
    /// `until expr`: an array ends after the element for which expr holds.
    pub until: Option<ExprNode>,
    /// `term 0x0d 0x0a [optional]`: bytes or text end at this sequence.
    pub term: Option<(Vec<u64>, bool)>,
    /// `latin1`, `utf16le`, ...: how a string's characters become bytes.
    pub encoding: Option<TextEncoding>,
    /// Arguments for a packet type's parameters.
    pub args: Vec<ExprNode>,
    /// `at [root] offset`.
    pub at: Option<AtExpr>,
    pub rules: FieldRules,
    pub span: Span,
}

/// `at [root] offset` after a field.
#[derive(Debug, Clone, PartialEq)]
pub struct AtExpr {
    pub offset: ExprNode,
    /// `at root`: from the start of the whole input rather than the packet.
    pub root: bool,
}

/// A packet parameter: `version uint8` in `packet Body(version uint8)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParamExpr {
    pub name: String,
    pub ty: TypeNode,
    pub span: Span,
}

/// `size n [exact]` after a field.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowExpr {
    pub size: ExprNode,
    /// The content must fill the window exactly.
    pub exact: bool,
}

/// `name switch selector { values => arm Type, ..., _ => other Type }`.
#[derive(Debug, Clone, PartialEq)]
pub struct SwitchExpr {
    pub id: String,
    pub selector: ExprNode,
    pub arms: Vec<ArmExpr>,
    pub align: Option<u64>,
    pub window: Option<WindowExpr>,
    pub span: Span,
}

/// One arm of a union.
#[derive(Debug, Clone, PartialEq)]
pub struct ArmExpr {
    /// `@range`: the versions in which the arm exists.
    pub versions: Option<VersionRange>,
    /// The selector values that pick this arm; None for the default (`_`).
    pub values: Option<Vec<ExprNode>>,
    pub name: String,
    /// The arm's type, length and byte order; None for an empty arm.
    pub ty: Option<(TypeNode, Option<ArrayLength>, Option<Endianness>)>,
    /// Arguments for a packet arm's parameters.
    pub args: Vec<ExprNode>,
    pub span: Span,
}

/// Validation written after a field's type.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FieldRules {
    /// `: Category strict`: only the category's values are valid.
    pub strict: bool,
    pub constraint: Option<Constraint>,
    /// `lenient`: keep the value even when a check fails.
    pub lenient: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Constraint {
    /// `== value`
    Equals(ExprNode),
    /// `in lo..hi`, inclusive
    Range(ExprNode, ExprNode),
    /// A different check per range of protocol versions: (versions,
    /// check), the latest first. Built by analysis from re-declarations.
    Versioned(Vec<(ExprNode, Constraint)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    /// The first member occupies the most significant bits (network convention).
    Msb,
    /// The first member occupies the least significant bits (C compilers on x86).
    Lsb,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitfieldMember {
    /// `_` marks explicit padding.
    pub name: String,
    pub width: u32,
    pub signed: bool,
    pub category: Option<(String, Span)>,
    pub rules: FieldRules,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitfieldExpr {
    pub id: String,
    /// Container type: a standard integer type or a `uN` type.
    pub container: TypeNode,
    pub endianness: Option<Endianness>,
    pub order: BitOrder,
    pub align: Option<u64>,
    pub members: Vec<BitfieldMember>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CalculatedField {
    pub name: String,
    pub data_type: TypeNode,
    pub expr: Box<ExprNode>,
    pub span: Span,
}

/// One entry of a packet body, in source order.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // a parse tree, built once
pub enum PacketItem {
    Field(TypeExpr),
    Bitfield(BitfieldExpr),
    Calculated(CalculatedField),
    /// `align N` on its own: pad to a multiple of N bytes from the packet start.
    Align(u64, Span),
    /// `assert expr "message"`
    Assert(AssertExpr),
    /// A tagged union.
    Switch(SwitchExpr),
    /// `@3 retries = 5`: a re-declaration that keeps the field's type and
    /// changes only its derivation or check for some versions.
    Override(OverrideExpr),
}

/// `name = expr`, `name == v` or `name in a..b` after `@range`, without a type.
#[derive(Debug, Clone, PartialEq)]
pub struct OverrideExpr {
    pub id: String,
    pub derive: Option<ExprNode>,
    pub placeholder: Option<ExprNode>,
    pub rules: FieldRules,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssertExpr {
    pub expr: ExprNode,
    /// The expression as written, for the default message.
    pub source: String,
    pub message: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExpr {
    pub name: String,
    pub params: Vec<ParamExpr>,
    pub items: Vec<PacketItem>,
    pub endianness: Option<Endianness>,
    /// `packet P align N`: C-struct-like natural alignment, packed to N bytes.
    pub align: Option<u64>,
    /// `@range` of each item (same order as `items`).
    pub versions: Vec<Option<VersionRange>>,
    pub span: Span,
}

/// How a constant's value was written, so generated code can keep the spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Radix {
    #[default]
    Dec,
    Hex,
    Bin,
}

/// One named value: `NAME = expr "note"`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstItem {
    /// `@range` on a category member.
    pub versions: Option<VersionRange>,
    pub name: String,
    pub value: ExprNode,
    pub note: Option<String>,
    pub radix: Radix,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConstKind {
    /// `const NAME type = value`
    Single(ConstItem),
    /// `const Category type { a = 1, b = 2 }`
    Group(Vec<ConstItem>),
}

/// A file-level `const` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstDecl {
    /// `@range` before `const`.
    pub versions: Option<VersionRange>,
    pub name: String,
    pub ty: TypeNode,
    pub kind: ConstKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExprList {
    pub packets: Vec<PacketExpr>,
    /// Named constants, in source order.
    pub constants: Vec<ConstDecl>,
    /// Bits in a `word` (16 unless the file says `wordsize 32`).
    pub word_size: u32,
    /// `import "file"` declarations: the path as written, and where.
    pub imports: Vec<(String, Span)>,
    pub dissectors: Vec<DissectorExpr>,
    /// `version N`: the protocol has versions 1..N, N being the latest.
    pub version: Option<(u32, Span)>,
}

impl TypeNode {
    /// Width in bits of a single element, or None for packet references.
    pub fn bit_width(&self) -> Option<u32> {
        Some(match self {
            TypeNode::UnsignedInteger8 | TypeNode::Integer8 | TypeNode::Bytes | TypeNode::Char => 8,
            TypeNode::Str | TypeNode::CStr | TypeNode::PrefixedStr { .. } => 8,
            TypeNode::UnsignedInteger16 | TypeNode::Integer16 => 16,
            TypeNode::UnsignedInteger32 | TypeNode::Integer32 | TypeNode::Float32 => 32,
            TypeNode::UnsignedInteger64 | TypeNode::Integer64 | TypeNode::Float64 | TypeNode::DateTime => 64,
            TypeNode::MacAddress => 48,
            TypeNode::Bits { width, .. } => *width,
            TypeNode::Varint(_) => 64,
            TypeNode::Packet(_) => return None,
        })
    }

    /// (width, signed) for integer-like types.
    pub fn integer_info(&self) -> Option<(u32, bool)> {
        Some(match self {
            TypeNode::UnsignedInteger8 | TypeNode::Bytes | TypeNode::Char => (8, false),
            TypeNode::Integer8 => (8, true),
            TypeNode::UnsignedInteger16 => (16, false),
            TypeNode::Integer16 => (16, true),
            TypeNode::UnsignedInteger32 => (32, false),
            TypeNode::Integer32 => (32, true),
            TypeNode::UnsignedInteger64 => (64, false),
            TypeNode::Integer64 | TypeNode::DateTime => (64, true),
            TypeNode::Bits { width, signed } => (*width, *signed),
            TypeNode::Varint(k) => (64, k.signed()),
            _ => return None,
        })
    }
}

/// `dissector Packet { name "...", abbrev "...", tcp.port 5190, heuristic }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DissectorExpr {
    pub packet: String,
    /// `name "..."`, `abbrev "..."` and any other quoted option.
    pub strings: Vec<(String, String, Span)>,
    /// `table value` registrations.
    pub tables: Vec<(String, u64)>,
    pub heuristic: bool,
    pub span: Span,
}
