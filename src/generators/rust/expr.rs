//! Rust spelling of expressions.

use super::naming::{Rust, scalar_type};
use crate::generators::common::{ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Func, Ty, ValueType, storage_for};

impl ExprLang for Scope<'_, Rust> {
    fn int_lit(&self, v: i64) -> String {
        format!("({}i64)", v)
    }

    fn float_lit(&self, v: f64) -> String {
        format!("({:?}f64)", v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let t = if ty == Ty::Float { "f64" } else { "i64" };
        format!("({} as {})", self.place(member), t)
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let (t, zero) = if ty == Ty::Float { ("f64", "0.0") } else { ("i64", "0") };
        format!(
            "(usize::try_from({}).ok().and_then(|i| {}.get(i)).map(|v| *v as {}).unwrap_or({}))",
            index,
            self.place(member),
            t,
            zero
        )
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let place = self.place(member);
        match (op, ty) {
            (AggOp::Sum, Ty::Float) => format!("{}.iter().map(|v| *v as f64).sum::<f64>()", place),
            (AggOp::Product, Ty::Float) => format!("{}.iter().map(|v| *v as f64).product::<f64>()", place),
            (AggOp::Sum, _) => format!("{}.iter().fold(0i64, |a, v| a.wrapping_add(*v as i64))", place),
            (AggOp::Product, _) => format!("{}.iter().fold(1i64, |a, v| a.wrapping_mul(*v as i64))", place),
        }
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            return match op {
                ArithOp::Add => format!("({} + {})", a, b),
                ArithOp::Sub => format!("({} - {})", a, b),
                ArithOp::Mul => format!("({} * {})", a, b),
                ArithOp::Div => format!("({} / {})", a, b),
                ArithOp::Pow => format!("{}.powf({})", a, b),
            };
        }
        match op {
            ArithOp::Add => format!("{}.wrapping_add({})", a, b),
            ArithOp::Sub => format!("{}.wrapping_sub({})", a, b),
            ArithOp::Mul => format!("{}.wrapping_mul({})", a, b),
            ArithOp::Div => format!("pb_div({}, {})", a, b),
            ArithOp::Pow => format!("pb_pow({}, {})", a, b),
        }
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("(if {} {{ {} }} else {{ {} }})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("{}.sqrt()", args[0]),
            Func::Min => format!("{}.min({})", args[0], args[1]),
            Func::Max => format!("{}.max({})", args[0], args[1]),
        }
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("({} as i64)", e),
            (Ty::Bool, Ty::Float) => format!("(({}) as i64 as f64)", e),
            (Ty::Int, Ty::Float) => format!("({} as f64)", e),
            (Ty::Float, Ty::Int) => format!("({} as i64)", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0.0)", e),
            _ => e,
        }
    }
}

/// Convert an i64/f64 expression to a member's storage type.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            let st = scalar_type(ty);
            if *width == storage_for(*width) {
                format!("({}) as {}", expr, st)
            } else {
                format!("pb_trunc({}, {}, {}) as {}", expr, width, signed, st)
            }
        }
        ValueType::Float { width } => format!("({}) as f{}", expr, width),
        _ => expr,
    }
}
