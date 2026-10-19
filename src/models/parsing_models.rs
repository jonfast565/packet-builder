#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endianness {
    Le,
    Be,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprNode {
    NoExpr,
    UnsignedInteger64Value(u64),
    Integer64Value(i64),
    Float64Value(f64),
    StringValue(String),

    // identifiers and optional index expression (e.g., foo[expr])
    ValueReference(String, Option<Box<ExprNode>>),

    // function call: name(args...)
    ActivationRecord(String, Vec<Box<ExprNode>>),

    ParenthesizedExpr(Box<ExprNode>),
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
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitfieldExpr {
    pub id: String,
    /// Container type: a standard integer type or a `uN` type.
    pub container: TypeNode,
    pub endianness: Option<Endianness>,
    pub order: BitOrder,
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExpr {
    pub name: String,
    pub items: Vec<PacketItem>,
    pub endianness: Option<Endianness>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExprList {
    pub packets: Vec<PacketExpr>,
}

impl TypeNode {
    /// Width in bits of a single element, or None for packet references.
    pub fn bit_width(&self) -> Option<u32> {
        Some(match self {
            TypeNode::UnsignedInteger8 | TypeNode::Integer8 | TypeNode::Bytes => 8,
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
            TypeNode::UnsignedInteger8 | TypeNode::Bytes => (8, false),
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

/// Evaluate an expression that only involves constants.
pub fn eval_const(expr: &ExprNode) -> Option<i128> {
    eval_i128(expr)
}

fn eval_i128(e: &ExprNode) -> Option<i128> {
    use ExprNode::*;

    match e {
        UnsignedInteger64Value(u) => Some(*u as i128),
        Integer64Value(i) => Some(*i as i128),
        Float64Value(f) => Some(*f as i128), // truncation
        StringValue(_) => None,

        ParenthesizedExpr(inner) => eval_i128(inner),

        Plus(a, b) => Some(eval_i128(a)? + eval_i128(b)?),
        Minus(a, b) => Some(eval_i128(a)? - eval_i128(b)?),
        Mult(a, b) => Some(eval_i128(a)? * eval_i128(b)?),
        Div(a, b) => {
            let rhs = eval_i128(b)?;
            if rhs == 0 { None } else { Some(eval_i128(a)? / rhs) }
        }
        Pow(a, b) => {
            let base = eval_i128(a)?;
            let exp = eval_i128(b)?;
            if exp < 0 {
                return None;
            }
            Some(ipow_i128(base, exp as u32)?)
        }

        GuardExpression(cond, then_e, else_e) => {
            let c = eval_bool(cond)?;
            if c { eval_i128(then_e) } else { eval_i128(else_e) }
        }

        // booleans as integers (rarely needed directly, but helpful for guards)
        Gt(a, b) => Some((eval_i128(a)? > eval_i128(b)?) as i128),
        Gte(a, b) => Some((eval_i128(a)? >= eval_i128(b)?) as i128),
        Lt(a, b) => Some((eval_i128(a)? < eval_i128(b)?) as i128),
        Lte(a, b) => Some((eval_i128(a)? <= eval_i128(b)?) as i128),
        Equals(a, b) => Some((eval_i128(a)? == eval_i128(b)?) as i128),
        NotEquals(a, b) => Some((eval_i128(a)? != eval_i128(b)?) as i128),

        And(a, b) => Some((eval_bool(a)? && eval_bool(b)?) as i128),
        Or(a, b) => Some((eval_bool(a)? || eval_bool(b)?) as i128),

        // Non-constant constructs we cannot resolve here (need runtime context):
        ValueReference(_, _) | ActivationRecord(_, _) | AggregateSum(_) | AggregateProduct(_) => None,

        NoExpr => None,
    }
}

fn eval_bool(e: &ExprNode) -> Option<bool> {
    use ExprNode::*;
    match e {
        Gt(a, b) => Some(eval_i128(a)? > eval_i128(b)?),
        Gte(a, b) => Some(eval_i128(a)? >= eval_i128(b)?),
        Lt(a, b) => Some(eval_i128(a)? < eval_i128(b)?),
        Lte(a, b) => Some(eval_i128(a)? <= eval_i128(b)?),
        Equals(a, b) => Some(eval_i128(a)? == eval_i128(b)?),
        NotEquals(a, b) => Some(eval_i128(a)? != eval_i128(b)?),
        And(a, b) => Some(eval_bool(a)? && eval_bool(b)?),
        Or(a, b) => Some(eval_bool(a)? || eval_bool(b)?),
        ParenthesizedExpr(inner) => eval_bool(inner),
        // allow numeric-as-bool (nonzero -> true) if it's a pure constant
        UnsignedInteger64Value(_) | Integer64Value(_) | Float64Value(_) => Some(eval_i128(e)? != 0),
        _ => None,
    }
}

fn ipow_i128(mut base: i128, mut exp: u32) -> Option<i128> {
    let mut acc: i128 = 1;
    while exp > 0 {
        if (exp & 1) == 1 {
            acc = acc.checked_mul(base)?;
        }
        exp >>= 1;
        if exp > 0 {
            base = base.checked_mul(base)?;
        }
    }
    Some(acc)
}
