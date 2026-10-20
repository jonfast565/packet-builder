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
    pub span: Span,
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
pub enum PacketItem {
    Field(TypeExpr),
    Bitfield(BitfieldExpr),
    Calculated(CalculatedField),
    /// `align N` on its own: pad to a multiple of N bytes from the packet start.
    Align(u64, Span),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExpr {
    pub name: String,
    pub items: Vec<PacketItem>,
    pub endianness: Option<Endianness>,
    /// `packet P align N`: C-struct-like natural alignment, packed to N bytes.
    pub align: Option<u64>,
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
            _ => return None,
        })
    }
}
