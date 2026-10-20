//! Python spelling of expressions.

use super::naming::Python;
use crate::generators::common::Mode;
use crate::generators::common::{Dialect, ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, Func, LogicOp, Ty, UnaryOp, ValueType};

/// u64 values must wrap to i64 to match the other languages.
fn needs_wrap(ty: &ValueType) -> bool {
    matches!(ty, ValueType::Int { width: 64, signed: false })
}

impl ExprLang for Scope<'_, Python> {
    fn int_lit(&self, v: i64) -> String {
        if v < 0 { format!("({})", v) } else { v.to_string() }
    }

    fn float_lit(&self, v: f64) -> String {
        format!("{:?}", v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let place = self.place(member);
        match ty {
            Ty::Float => format!("float({})", place),
            _ if needs_wrap(&self.packet.members[member].ty) => format!("_pb_wrap({})", place),
            _ => place,
        }
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let v = format!("_pb_at({}, {})", self.place(member), index);
        match ty {
            Ty::Float => format!("float({})", v),
            _ if needs_wrap(&self.packet.members[member].ty) => format!("_pb_wrap({})", v),
            _ => v,
        }
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let place = self.place(member);
        match (op, ty) {
            (AggOp::Sum, Ty::Float) => format!("math.fsum(float(v) for v in {})", place),
            (AggOp::Product, Ty::Float) => format!("math.prod(float(v) for v in {})", place),
            (AggOp::Sum, _) => format!("_pb_wrap(sum({}))", place),
            (AggOp::Product, _) => format!("_pb_wrap(math.prod({}))", place),
        }
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            return match op {
                ArithOp::Add => format!("({} + {})", a, b),
                ArithOp::Sub => format!("({} - {})", a, b),
                ArithOp::Mul => format!("({} * {})", a, b),
                ArithOp::Div => format!("_pb_fdiv({}, {})", a, b),
                ArithOp::Pow => format!("_pb_fpow({}, {})", a, b),
                _ => unreachable!("integer-only operator on floats"),
            };
        }
        match op {
            ArithOp::Add => format!("_pb_wrap({} + {})", a, b),
            ArithOp::Sub => format!("_pb_wrap({} - {})", a, b),
            ArithOp::Mul => format!("_pb_wrap({} * {})", a, b),
            ArithOp::Div => format!("_pb_div({}, {})", a, b),
            ArithOp::Pow => format!("_pb_pow({}, {})", a, b),
            ArithOp::Mod => format!("_pb_mod({}, {})", a, b),
            ArithOp::Shl => format!("_pb_shl({}, {})", a, b),
            ArithOp::Shr => format!("_pb_shr({}, {})", a, b),
            ArithOp::BitAnd => format!("({} & {})", a, b),
            ArithOp::BitOr => format!("({} | {})", a, b),
            ArithOp::BitXor => format!("({} ^ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("_pb_wrap(-{})", e),
            (UnaryOp::BitNot, _) => format!("(~{})", e),
            (UnaryOp::Not, _) => format!("(not {})", e),
        }
    }

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "and" } else { "or" };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("({} if {} else {})", then, cond, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("_pb_sqrt({})", args[0]),
            Func::Min => format!("min({}, {})", args[0], args[1]),
            Func::Max => format!("max({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        match self.member(member).ty {
            ValueType::Str => format!("len({}.encode(\"utf-8\"))", self.place(member)),
            _ => format!("len({})", self.place(member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) // 8)", to, from)
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pb_w" } else { "pb_r" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("{}.checksum({}, {}, {}, {}, {})", rw, algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, _ty: Ty) -> String {
        match field {
            Some((_, f)) => format!("pb_last.{}", super::naming::ident(f)),
            None => "pb_last".into(),
        }
    }

    fn param(&self, index: usize) -> String {
        self.param_var(index)
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("int({})", e),
            (Ty::Bool, Ty::Float) | (Ty::Int, Ty::Float) => format!("float({})", e),
            (Ty::Float, Ty::Int) => format!("_pb_ftoi({})", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0.0)", e),
            _ => e,
        }
    }
}

pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            format!("_pb_trunc({}, {}, {})", expr, width, Python::flag(*signed))
        }
        ValueType::Float { width: 32 } => format!("_pb_f32({})", expr),
        _ => expr,
    }
}
