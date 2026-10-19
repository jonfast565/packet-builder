//! Expression emission: [`emit_expr`] walks a [`TExpr`] and asks an
//! [`ExprLang`] for the target-language spelling of each node (Visitor).

use crate::ir::{AggOp, ArithOp, CmpOp, Func, LogicOp, TExpr, Ty};

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
    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String;
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
    }
}
