//! C spelling of expressions.

use super::naming::{C, helper_suffix, len_ident, scalar_type};
use crate::generators::common::{Dialect, ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Func, Ty, UnaryOp, ValueType, storage_for};

impl Scope<'_, C> {
    /// The element count of array member `member`.
    fn len(&self, member: usize) -> String {
        format!("p->{}", len_ident(self.packet, self.member(member)))
    }
}

impl ExprLang for Scope<'_, C> {
    fn int_lit(&self, v: i64) -> String {
        if v == i64::MIN {
            "(-INT64_C(9223372036854775807) - 1)".into()
        } else if v < 0 {
            format!("(-INT64_C({}))", -v)
        } else {
            format!("INT64_C({})", v)
        }
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let t = if ty == Ty::Float { "double" } else { "int64_t" };
        format!("(({}){})", t, self.place(member))
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let t = if ty == Ty::Float { "double" } else { "int64_t" };
        let m = &self.packet.members[member];
        format!("(({})pb_at_{}({}, {}, {}))", t, helper_suffix(&m.ty), self.place(member), self.len(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let m = &self.packet.members[member];
        let f = match (op, ty) {
            (AggOp::Sum, Ty::Float) => "sumf",
            (AggOp::Product, Ty::Float) => "prodf",
            (AggOp::Sum, _) => "sum",
            (AggOp::Product, _) => "prod",
        };
        format!("pb_{}_{}({}, {})", f, helper_suffix(&m.ty), self.place(member), self.len(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            return match op {
                ArithOp::Add => format!("({} + {})", a, b),
                ArithOp::Sub => format!("({} - {})", a, b),
                ArithOp::Mul => format!("({} * {})", a, b),
                ArithOp::Div => format!("({} / {})", a, b),
                ArithOp::Pow => format!("pow({}, {})", a, b),
                _ => unreachable!("integer-only operator on floats"),
            };
        }
        let f = match op {
            ArithOp::Add => "pb_add",
            ArithOp::Sub => "pb_sub",
            ArithOp::Mul => "pb_mul",
            ArithOp::Div => "pb_div",
            ArithOp::Pow => "pb_pow",
            ArithOp::Mod => "pb_mod",
            ArithOp::Shl => "pb_shl",
            ArithOp::Shr => "pb_shr",
            ArithOp::BitAnd => return format!("({} & {})", a, b),
            ArithOp::BitOr => return format!("({} | {})", a, b),
            ArithOp::BitXor => return format!("({} ^ {})", a, b),
        };
        format!("{}({}, {})", f, a, b)
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("pb_neg({})", e),
            (UnaryOp::BitNot, _) => format!("(~{})", e),
            (UnaryOp::Not, _) => format!("(!{})", e),
        }
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("({} ? {} : {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String {
        let s = if ty == Ty::Float { "f" } else { "i" };
        match func {
            Func::Sqrt => format!("sqrt({})", args[0]),
            Func::Min => format!("pb_min_{}({}, {})", s, args[0], args[1]),
            Func::Max => format!("pb_max_{}({}, {})", s, args[0], args[1]),
        }
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("((int64_t)({}))", e),
            (Ty::Bool, Ty::Float) | (Ty::Int, Ty::Float) => format!("((double)({}))", e),
            (Ty::Float, Ty::Int) => format!("pb_ftoi({})", e),
            (Ty::Int, Ty::Bool) | (Ty::Float, Ty::Bool) => format!("(({}) != 0)", e),
            _ => e,
        }
    }
}

pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            let st = scalar_type(ty);
            if *width == storage_for(*width) {
                format!("({})({})", st, expr)
            } else {
                format!("({})pb_trunc({}, {}, {})", st, expr, width, C::flag(*signed))
            }
        }
        _ => format!("({})({})", scalar_type(ty), expr),
    }
}
