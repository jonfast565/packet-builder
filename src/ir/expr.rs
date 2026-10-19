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
}

impl TExpr {
    pub fn ty(&self) -> Ty {
        match self {
            TExpr::IntLit(_) => Ty::Int,
            TExpr::FloatLit(_) => Ty::Float,
            TExpr::Ref { ty, .. }
            | TExpr::Index { ty, .. }
            | TExpr::Aggregate { ty, .. }
            | TExpr::Arith { ty, .. }
            | TExpr::Guard { ty, .. }
            | TExpr::Call { ty, .. } => *ty,
            TExpr::Cmp { .. } | TExpr::Logic { .. } => Ty::Bool,
            TExpr::Convert { to, .. } => *to,
        }
    }

    /// Members this expression reads.
    pub fn deps(&self, out: &mut Vec<usize>) {
        match self {
            TExpr::IntLit(_) | TExpr::FloatLit(_) => {}
            TExpr::Ref { member, .. } | TExpr::Aggregate { member, .. } => out.push(*member),
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
            TExpr::Convert { e, .. } => e.deps(out),
        }
    }

    /// Value of an integer expression made only of literals.
    pub fn const_int(&self) -> Option<i64> {
        match self {
            TExpr::IntLit(v) => Some(*v),
            TExpr::Arith { op, a, b, ty: Ty::Int } => {
                let (a, b) = (a.const_int()?, b.const_int()?);
                Some(match op {
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
                })
            }
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
