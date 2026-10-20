//! Expression emission: [`emit_expr`] walks a [`TExpr`] and asks an
//! [`ExprLang`] for the target-language spelling of each node (Visitor).

use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, LogicOp, Mark, TExpr, Ty, UnaryOp};

/// Whether an expression is evaluated while decoding (every member lives in
/// the target struct) or while encoding (calculated members are locals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Decode,
    Encode,
}

/// Language hooks used by [`emit_expr`]. Integer expressions have type i64,
/// float expressions f64 and boolean expressions the native bool.
pub trait ExprLang {
    fn int_lit(&self, v: i64) -> String;
    fn float_lit(&self, v: f64) -> String {
        format!("{:?}", v)
    }
    /// A scalar member converted to i64 (Ty::Int) or f64 (Ty::Float).
    fn member_ref(&self, member: usize, ty: Ty) -> String;
    /// Element `index` (an i64 expression) of an array member; 0 if out of range.
    fn index(&self, member: usize, index: String, ty: Ty) -> String;
    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String;
    /// Binary arithmetic. The integer-only operators (`ArithOp::int_only`)
    /// are never called with `Ty::Float`.
    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String;
    /// `-x` (wrapping for integers), `~x` (integers) or `not x` (booleans).
    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String;
    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        format!("({} {} {})", a, cmp_symbol(op), b)
    }
    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "&&" } else { "||" };
        format!("({} {} {})", a, sym, b)
    }
    fn guard(&self, cond: String, then: String, other: String, ty: Ty) -> String;
    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String;
    fn convert(&self, e: String, from: Ty, to: Ty) -> String;
    /// In an `until` condition: the element just read (`pb_last`), or its
    /// field (element packet name, field name).
    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String;
    /// Parameter `index` of the packet (named by `Scope::param_var`), as i64.
    fn param(&self, index: usize) -> String;
    /// Element count of an array member, or the byte length of a string, as i64.
    fn len(&self, member: usize) -> String;
    /// `remaining`: whole bytes the reader has left before the end of its
    /// window or input, as i64. Only emitted while decoding.
    fn remaining(&self) -> String;
    /// The struct's own value of derived `member` as i64, even while
    /// encoding (where `member_ref` reads the encode-time local).
    fn stored(&self, member: usize) -> String;
    /// Whole bytes between two recorded bit positions (variables), as i64.
    fn size(&self, from: &str, to: &str) -> String;
    /// A checksum of the bytes between two recorded bit positions; `hole`
    /// (two more positions) counts as zero. Read from the reader when
    /// decoding and from the writer when encoding, as i64.
    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String;
}

/// The variable that holds a recorded position.
pub fn mark_var(m: Mark) -> String {
    match m {
        Mark::PacketStart => "pb_start".into(),
        Mark::PacketEnd => "pbm_end".into(),
        Mark::Before(i) => format!("pbm_b{}", i),
        Mark::After(i) => format!("pbm_a{}", i),
    }
}

pub fn cmp_symbol(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Gt => ">",
        CmpOp::Gte => ">=",
        CmpOp::Lt => "<",
        CmpOp::Lte => "<=",
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
    }
}

pub fn emit_expr<L: ExprLang + ?Sized>(l: &L, e: &TExpr) -> String {
    match e {
        TExpr::IntLit(v) => l.int_lit(*v),
        TExpr::FloatLit(v) => l.float_lit(*v),
        TExpr::Ref { member, ty } => l.member_ref(*member, *ty),
        TExpr::Index { member, index, ty } => l.index(*member, emit_expr(l, index), *ty),
        TExpr::Aggregate { member, op, ty } => l.aggregate(*member, *op, *ty),
        TExpr::Arith { op, a, b, ty } => l.arith(*op, emit_expr(l, a), emit_expr(l, b), *ty),
        TExpr::Cmp { op, a, b } => l.cmp(*op, emit_expr(l, a), emit_expr(l, b)),
        TExpr::Logic { op, a, b } => l.logic(*op, emit_expr(l, a), emit_expr(l, b)),
        TExpr::Guard { cond, then, other, ty } => {
            l.guard(emit_expr(l, cond), emit_expr(l, then), emit_expr(l, other), *ty)
        }
        TExpr::Call { func, args, ty } => l.call(*func, args.iter().map(|a| emit_expr(l, a)).collect(), *ty),
        TExpr::Convert { e, to } => l.convert(emit_expr(l, e), e.ty(), *to),
        TExpr::Unary { op, e, ty } => l.unary(*op, emit_expr(l, e), *ty),
        TExpr::Len { member } => l.len(*member),
        TExpr::Param { index } => l.param(*index),
        TExpr::Remaining => l.remaining(),
        TExpr::Stored { member } => l.stored(*member),
        TExpr::Last { field, ty } => l.last(field.as_ref().map(|(p, f)| (p.as_str(), f.as_str())), *ty),
        TExpr::Size { from, to } => l.size(&mark_var(*from), &mark_var(*to)),
        TExpr::Checksum { algo, from, to, hole } => {
            let hole = hole.map(|(a, b)| (mark_var(a), mark_var(b)));
            l.checksum(*algo, &mark_var(*from), &mark_var(*to), hole.as_ref().map(|(a, b)| (a.as_str(), b.as_str())))
        }
    }
}
