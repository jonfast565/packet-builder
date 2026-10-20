//! Zig spelling of expressions.

use super::naming::{Zig, scalar_type};
use crate::generators::common::Mode;
use crate::generators::common::{ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, Func, LogicOp, Ty, UnaryOp, ValueType};

impl ExprLang for Scope<'_, Zig> {
    fn int_lit(&self, v: i64) -> String {
        format!("@as(i64, {})", v)
    }

    fn float_lit(&self, v: f64) -> String {
        format!("@as(f64, {:?})", v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let f = if ty == Ty::Float { "pbF64" } else { "pbI64" };
        format!("{}({})", f, self.place(member))
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let f = if ty == Ty::Float { "pbF64" } else { "pbI64" };
        format!("{}(pbAt({}, {}))", f, self.place(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let f = match (op, ty) {
            (AggOp::Sum, Ty::Float) => "pbSumF",
            (AggOp::Product, Ty::Float) => "pbProdF",
            (AggOp::Sum, _) => "pbSum",
            (AggOp::Product, _) => "pbProd",
        };
        format!("{}({})", f, self.place(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        match (op, ty) {
            (ArithOp::Add, Ty::Float) => format!("({} + {})", a, b),
            (ArithOp::Sub, Ty::Float) => format!("({} - {})", a, b),
            (ArithOp::Mul, Ty::Float) => format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => format!("({} / {})", a, b),
            (ArithOp::Pow, Ty::Float) => format!("std.math.pow(f64, {}, {})", a, b),
            (ArithOp::Add, _) => format!("({} +% {})", a, b),
            (ArithOp::Sub, _) => format!("({} -% {})", a, b),
            (ArithOp::Mul, _) => format!("({} *% {})", a, b),
            (ArithOp::Div, _) => format!("pbDiv({}, {})", a, b),
            (ArithOp::Pow, _) => format!("pbPow({}, {})", a, b),
            (ArithOp::Mod, _) => format!("pbMod({}, {})", a, b),
            (ArithOp::Shl, _) => format!("pbShl({}, {})", a, b),
            (ArithOp::Shr, _) => format!("pbShr({}, {})", a, b),
            (ArithOp::BitAnd, _) => format!("({} & {})", a, b),
            (ArithOp::BitOr, _) => format!("({} | {})", a, b),
            (ArithOp::BitXor, _) => format!("({} ^ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("(0 -% {})", e),
            (UnaryOp::BitNot, _) => format!("(~{})", e),
            (UnaryOp::Not, _) => format!("(!{})", e),
        }
    }

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "and" } else { "or" };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("(if ({}) {} else {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("@sqrt({})", args[0]),
            Func::Min => format!("@min({}, {})", args[0], args[1]),
            Func::Max => format!("@max({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        format!("@as(i64, @intCast({}.len))", self.place(member))
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("@as(i64, @intCast(({} - {}) / 8))", to, from)
    }

    fn stored(&self, member: usize) -> String {
        format!("pbI64({})", self.field(self.member(member)))
    }

    fn remaining(&self) -> String {
        "pb_r.remainingBytes()".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pb_w" } else { "pb_r" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("@as(i64, @bitCast({}.checksum({}, {}, {}, {}, {})))", rw, algo.id(), from, to, hf, ht)
    }

    fn param(&self, index: usize) -> String {
        format!("pbI64({})", self.param_var(index))
    }

    /// The element just appended to `pb_l` by a repeat-until loop.
    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let f = if ty == Ty::Float { "pbF64" } else { "pbI64" };
        match field {
            Some((_, name)) => format!("{}(pb_l.items[pb_l.items.len - 1].{})", f, super::naming::ident(name)),
            None => format!("{}(pb_l.items[pb_l.items.len - 1])", f),
        }
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("@as(i64, @intFromBool({}))", e),
            (Ty::Bool, Ty::Float) => format!("@as(f64, @floatFromInt(@intFromBool({})))", e),
            (Ty::Int, Ty::Float) => format!("@as(f64, @floatFromInt({}))", e),
            (Ty::Float, Ty::Int) => format!("pbFtoI({})", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0)", e),
            _ => e,
        }
    }
}

pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { .. } => format!("pbStore({}, {})", scalar_type(ty), expr),
        ValueType::Float { width: 32 } => format!("@as(f32, @floatCast({}))", expr),
        _ => expr,
    }
}
