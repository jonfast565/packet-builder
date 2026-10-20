//! C# spelling of expressions.

use super::naming::{CSharp, scalar_type};
use crate::generators::common::Mode;
use crate::generators::common::{ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, Func, Ty, UnaryOp, ValueType, storage_for};

impl ExprLang for Scope<'_, CSharp> {
    fn int_lit(&self, v: i64) -> String {
        format!("({}L)", v)
    }

    fn float_lit(&self, v: f64) -> String {
        format!("({:?}d)", v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let t = if ty == Ty::Float { "double" } else { "long" };
        format!("(({}){})", t, self.place(member))
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let t = if ty == Ty::Float { "double" } else { "long" };
        format!("(({})Pb.At({}, {}))", t, self.place(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let place = self.place(member);
        match (op, ty) {
            (AggOp::Sum, Ty::Float) => format!("{}.Aggregate(0.0d, (pbA, pbV) => pbA + (double)pbV)", place),
            (AggOp::Product, Ty::Float) => format!("{}.Aggregate(1.0d, (pbA, pbV) => pbA * (double)pbV)", place),
            (AggOp::Sum, _) => format!("{}.Aggregate(0L, (pbA, pbV) => unchecked(pbA + (long)pbV))", place),
            (AggOp::Product, _) => format!("{}.Aggregate(1L, (pbA, pbV) => unchecked(pbA * (long)pbV))", place),
        }
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        match (op, ty) {
            (ArithOp::Add, _) => format!("({} + {})", a, b),
            (ArithOp::Sub, _) => format!("({} - {})", a, b),
            (ArithOp::Mul, _) => format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => format!("({} / {})", a, b),
            (ArithOp::Div, _) => format!("Pb.Div({}, {})", a, b),
            (ArithOp::Pow, Ty::Float) => format!("Math.Pow({}, {})", a, b),
            (ArithOp::Pow, _) => format!("Pb.Pow({}, {})", a, b),
            (ArithOp::Mod, _) => format!("Pb.Mod({}, {})", a, b),
            (ArithOp::Shl, _) => format!("Pb.Shl({}, {})", a, b),
            (ArithOp::Shr, _) => format!("Pb.Shr({}, {})", a, b),
            (ArithOp::BitAnd, _) => format!("({} & {})", a, b),
            (ArithOp::BitOr, _) => format!("({} | {})", a, b),
            (ArithOp::BitXor, _) => format!("({} ^ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("unchecked(-{})", e),
            (UnaryOp::BitNot, _) => format!("(~{})", e),
            (UnaryOp::Not, _) => format!("(!{})", e),
        }
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("({} ? {} : {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("Math.Sqrt({})", args[0]),
            Func::Min => format!("Math.Min({}, {})", args[0], args[1]),
            Func::Max => format!("Math.Max({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        match self.member(member).ty {
            ValueType::Str => format!("((long)System.Text.Encoding.UTF8.GetByteCount({}))", self.place(member)),
            _ => format!("((long){}.Length)", self.place(member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) / 8)", to, from)
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pbW" } else { "pbR" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("unchecked((long){}.Checksum({}, {}, {}, {}, {}))", rw, algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let t = if ty == Ty::Float { "double" } else { "long" };
        match field {
            Some((packet, f)) => format!("(({})pbLast.{})", t, super::naming::prop_name(packet, f)),
            None => format!("(({})pbLast)", t),
        }
    }

    fn param(&self, index: usize) -> String {
        format!("((long){})", self.param_var(index))
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("({} ? 1L : 0L)", e),
            (Ty::Bool, Ty::Float) => format!("({} ? 1.0d : 0.0d)", e),
            (Ty::Int, Ty::Float) => format!("((double)({}))", e),
            (Ty::Float, Ty::Int) => format!("Pb.FtoI({})", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0L)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0.0d)", e),
            _ => e,
        }
    }
}

/// Convert a long/double expression to a member's storage type. `unchecked`
/// gives wrapping semantics even for constant expressions.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            let st = scalar_type(ty);
            if *width == storage_for(*width) {
                format!("unchecked(({})({}))", st, expr)
            } else {
                format!("unchecked(({})Pb.Trunc({}, {}, {}))", st, expr, width, signed)
            }
        }
        _ => format!("unchecked(({})({}))", scalar_type(ty), expr),
    }
}
