//! Typed expressions: the result of type-checking an `ExprNode`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Int,
    Float,
    Bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Pow,
    /// Remainder with the sign of the dividend; `x % 0` is 0. Integers only.
    Mod,
    /// `<<`: a count outside 0..=63 gives 0. Integers only.
    Shl,
    /// `>>`: arithmetic shift; a count above 63 gives 0 or -1 (by sign), a
    /// negative count gives 0. Integers only.
    Shr,
    BitAnd,
    BitOr,
    BitXor,
}

impl ArithOp {
    /// Operators that only apply to integers.
    pub fn int_only(self) -> bool {
        matches!(self, ArithOp::Mod | ArithOp::Shl | ArithOp::Shr | ArithOp::BitAnd | ArithOp::BitOr | ArithOp::BitXor)
    }

    /// The operator applied to two i64 values with the documented semantics.
    pub fn apply(self, a: i64, b: i64) -> i64 {
        match self {
            ArithOp::Add => a.wrapping_add(b),
            ArithOp::Sub => a.wrapping_sub(b),
            ArithOp::Mul => a.wrapping_mul(b),
            ArithOp::Div => {
                if b == 0 {
                    0
                } else {
                    a.wrapping_div(b)
                }
            }
            ArithOp::Pow => {
                if b < 0 {
                    0
                } else {
                    a.wrapping_pow(b.min(u32::MAX as i64) as u32)
                }
            }
            ArithOp::Mod => {
                if b == 0 {
                    0
                } else {
                    a.wrapping_rem(b)
                }
            }
            ArithOp::Shl => {
                if (0..64).contains(&b) {
                    a.wrapping_shl(b as u32)
                } else {
                    0
                }
            }
            ArithOp::Shr => {
                if b < 0 {
                    0
                } else {
                    a >> b.min(63)
                }
            }
            ArithOp::BitAnd => a & b,
            ArithOp::BitOr => a | b,
            ArithOp::BitXor => a ^ b,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// `-x` (wrapping).
    Neg,
    /// `~x`, integers only.
    BitNot,
    /// `not x` on a boolean.
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggOp {
    Sum,
    Product,
}

/// A bit position recorded while decoding or encoding a packet, used by
/// `sizeof`, `offsetof` and checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mark {
    /// Where the packet starts.
    PacketStart,
    /// Before step `i` (during analysis: before source item `i`).
    Before(usize),
    /// After step `i` (during analysis: after source item `i`).
    After(usize),
    /// Where the packet ends.
    PacketEnd,
}

/// Checksum algorithms. CRCs follow the catalogue of parametrised CRC
/// algorithms (names in brackets); each runtime implements the same table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    /// CRC-8/SMBUS.
    Crc8,
    /// CRC-16/ARC.
    Crc16Arc,
    /// CRC-16/IBM-3740 (often called CCITT-FALSE).
    Crc16CcittFalse,
    /// CRC-16/XMODEM.
    Crc16Xmodem,
    /// CRC-16/KERMIT.
    Crc16Kermit,
    /// CRC-16/MODBUS.
    Crc16Modbus,
    /// CRC-32/ISO-HDLC (zlib, Ethernet).
    Crc32,
    /// CRC-32/ISCSI (Castagnoli).
    Crc32c,
    /// RFC 1071 Internet checksum (IPv4, TCP, UDP, ICMP).
    Internet,
    /// Fletcher-16.
    Fletcher16,
    /// Sum of the bytes, modulo 256.
    Sum8,
    /// XOR of the bytes.
    Xor8,
}

impl Checksum {
    pub const ALL: [Checksum; 12] = [
        Checksum::Crc8,
        Checksum::Crc16Arc,
        Checksum::Crc16CcittFalse,
        Checksum::Crc16Xmodem,
        Checksum::Crc16Kermit,
        Checksum::Crc16Modbus,
        Checksum::Crc32,
        Checksum::Crc32c,
        Checksum::Internet,
        Checksum::Fletcher16,
        Checksum::Sum8,
        Checksum::Xor8,
    ];

    /// The name used in packet descriptions.
    pub fn name(self) -> &'static str {
        match self {
            Checksum::Crc8 => "crc8",
            Checksum::Crc16Arc => "crc16_arc",
            Checksum::Crc16CcittFalse => "crc16_ccitt_false",
            Checksum::Crc16Xmodem => "crc16_xmodem",
            Checksum::Crc16Kermit => "crc16_kermit",
            Checksum::Crc16Modbus => "crc16_modbus",
            Checksum::Crc32 => "crc32",
            Checksum::Crc32c => "crc32c",
            Checksum::Internet => "internet",
            Checksum::Fletcher16 => "fletcher16",
            Checksum::Sum8 => "sum8",
            Checksum::Xor8 => "xor8",
        }
    }

    pub fn from_name(name: &str) -> Option<Checksum> {
        Checksum::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The number the runtimes use for this algorithm.
    pub fn id(self) -> u32 {
        Checksum::ALL.iter().position(|c| *c == self).expect("listed") as u32
    }

    /// Width of the result in bits.
    pub fn width(self) -> u32 {
        match self {
            Checksum::Crc8 | Checksum::Sum8 | Checksum::Xor8 => 8,
            Checksum::Crc32 | Checksum::Crc32c => 32,
            _ => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    Sqrt,
    Min,
    Max,
}

/// A type-checked expression. Integer arithmetic is 64-bit two's complement
/// (wrapping); integer division truncates toward zero and yields 0 when
/// dividing by zero; out-of-range array indexes yield 0. Every backend
/// implements exactly these semantics.
#[derive(Debug, Clone, PartialEq)]
pub enum TExpr {
    IntLit(i64),
    FloatLit(f64),
    /// Scalar member converted to i64 / f64.
    Ref {
        member: usize,
        ty: Ty,
    },
    /// Element of an array member.
    Index {
        member: usize,
        index: Box<TExpr>,
        ty: Ty,
    },
    Aggregate {
        member: usize,
        op: AggOp,
        ty: Ty,
    },
    Arith {
        op: ArithOp,
        a: Box<TExpr>,
        b: Box<TExpr>,
        ty: Ty,
    },
    Cmp {
        op: CmpOp,
        a: Box<TExpr>,
        b: Box<TExpr>,
    },
    Logic {
        op: LogicOp,
        a: Box<TExpr>,
        b: Box<TExpr>,
    },
    Guard {
        cond: Box<TExpr>,
        then: Box<TExpr>,
        other: Box<TExpr>,
        ty: Ty,
    },
    Call {
        func: Func,
        args: Vec<TExpr>,
        ty: Ty,
    },
    Convert {
        e: Box<TExpr>,
        to: Ty,
    },
    Unary {
        op: UnaryOp,
        e: Box<TExpr>,
        ty: Ty,
    },
    /// Element count of an array member (bytes of a string).
    Len {
        member: usize,
    },
    /// Whole bytes between two marks.
    Size {
        from: Mark,
        to: Mark,
    },
    /// A checksum of the bytes between two marks; the bytes of `hole` (the
    /// checksum field itself, when it is inside the range) count as zero.
    Checksum {
        algo: Checksum,
        from: Mark,
        to: Mark,
        hole: Option<(Mark, Mark)>,
    },
}

impl TExpr {
    pub fn ty(&self) -> Ty {
        match self {
            TExpr::IntLit(_) | TExpr::Len { .. } | TExpr::Size { .. } | TExpr::Checksum { .. } => Ty::Int,
            TExpr::FloatLit(_) => Ty::Float,
            TExpr::Ref { ty, .. }
            | TExpr::Index { ty, .. }
            | TExpr::Aggregate { ty, .. }
            | TExpr::Arith { ty, .. }
            | TExpr::Guard { ty, .. }
            | TExpr::Call { ty, .. }
            | TExpr::Unary { ty, .. } => *ty,
            TExpr::Cmp { .. } | TExpr::Logic { .. } => Ty::Bool,
            TExpr::Convert { to, .. } => *to,
        }
    }

    /// Members this expression reads.
    pub fn deps(&self, out: &mut Vec<usize>) {
        match self {
            TExpr::IntLit(_) | TExpr::FloatLit(_) | TExpr::Size { .. } | TExpr::Checksum { .. } => {}
            TExpr::Ref { member, .. } | TExpr::Aggregate { member, .. } | TExpr::Len { member } => out.push(*member),
            TExpr::Index { member, index, .. } => {
                out.push(*member);
                index.deps(out);
            }
            TExpr::Arith { a, b, .. } | TExpr::Cmp { a, b, .. } | TExpr::Logic { a, b, .. } => {
                a.deps(out);
                b.deps(out);
            }
            TExpr::Guard { cond, then, other, .. } => {
                cond.deps(out);
                then.deps(out);
                other.deps(out);
            }
            TExpr::Call { args, .. } => args.iter().for_each(|a| a.deps(out)),
            TExpr::Convert { e, .. } | TExpr::Unary { e, .. } => e.deps(out),
        }
    }

    /// Every child expression.
    fn children(&self) -> Vec<&TExpr> {
        match self {
            TExpr::Index { index, .. } => vec![index],
            TExpr::Arith { a, b, .. } | TExpr::Cmp { a, b, .. } | TExpr::Logic { a, b, .. } => vec![a, b],
            TExpr::Guard { cond, then, other, .. } => vec![cond, then, other],
            TExpr::Call { args, .. } => args.iter().collect(),
            TExpr::Convert { e, .. } | TExpr::Unary { e, .. } => vec![e],
            _ => Vec::new(),
        }
    }

    /// Call `f` on this expression and every sub-expression.
    pub fn visit_mut(&mut self, f: &mut dyn FnMut(&mut TExpr)) {
        f(self);
        match self {
            TExpr::Index { index, .. } => index.visit_mut(f),
            TExpr::Arith { a, b, .. } | TExpr::Cmp { a, b, .. } | TExpr::Logic { a, b, .. } => {
                a.visit_mut(f);
                b.visit_mut(f);
            }
            TExpr::Guard { cond, then, other, .. } => {
                cond.visit_mut(f);
                then.visit_mut(f);
                other.visit_mut(f);
            }
            TExpr::Call { args, .. } => args.iter_mut().for_each(|a| a.visit_mut(f)),
            TExpr::Convert { e, .. } | TExpr::Unary { e, .. } => e.visit_mut(f),
            _ => {}
        }
    }

    /// The positions this expression reads (`sizeof`, `offsetof`, checksums).
    pub fn marks(&self, out: &mut Vec<Mark>) {
        match self {
            TExpr::Size { from, to } => out.extend([*from, *to]),
            TExpr::Checksum { from, to, hole, .. } => {
                out.extend([*from, *to]);
                if let Some((a, b)) = hole {
                    out.extend([*a, *b]);
                }
            }
            e => e.children().into_iter().for_each(|c| c.marks(out)),
        }
    }

    /// The checksums this expression computes, with their ranges.
    pub fn checksums(&self, out: &mut Vec<(Mark, Mark)>) {
        match self {
            TExpr::Checksum { from, to, .. } => out.push((*from, *to)),
            e => e.children().into_iter().for_each(|c| c.checksums(out)),
        }
    }

    /// Rewrite every mark (item indexes to step indexes after layout).
    pub fn map_marks(&mut self, f: &impl Fn(Mark) -> Mark) {
        self.visit_mut(&mut |e| match e {
            TExpr::Size { from, to } => {
                *from = f(*from);
                *to = f(*to);
            }
            TExpr::Checksum { from, to, hole, .. } => {
                *from = f(*from);
                *to = f(*to);
                if let Some((a, b)) = hole {
                    *a = f(*a);
                    *b = f(*b);
                }
            }
            _ => {}
        });
    }

    /// Value of an integer expression made only of literals.
    pub fn const_int(&self) -> Option<i64> {
        match self {
            TExpr::IntLit(v) => Some(*v),
            TExpr::Arith { op, a, b, ty: Ty::Int } => Some(op.apply(a.const_int()?, b.const_int()?)),
            TExpr::Unary { op: UnaryOp::Neg, e, ty: Ty::Int } => Some(e.const_int()?.wrapping_neg()),
            TExpr::Unary { op: UnaryOp::BitNot, e, .. } => Some(!e.const_int()?),
            _ => None,
        }
    }
}

/// Numeric type of a binary operation: float wins, booleans count as integers.
pub(crate) fn numeric_join(a: Ty, b: Ty) -> Ty {
    if a == Ty::Float || b == Ty::Float { Ty::Float } else { Ty::Int }
}

pub fn coerce(e: TExpr, to: Ty) -> TExpr {
    if e.ty() == to {
        return e;
    }
    TExpr::Convert { e: Box::new(e), to }
}
