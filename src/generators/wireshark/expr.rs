//! Lua spelling of expressions. Lua 5.4 integers are 64-bit and wrap, which
//! is exactly the semantics every runtime implements.

use super::naming::Lua;
use crate::generators::common::{ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, Ty, UnaryOp, ValueType};

impl ExprLang for Scope<'_, Lua> {
    fn int_lit(&self, v: i64) -> String {
        if v == i64::MIN {
            "math.mininteger".into()
        } else if v < 0 {
            format!("({})", v)
        } else {
            v.to_string()
        }
    }

    fn float_lit(&self, v: f64) -> String {
        if v.is_nan() {
            "(0.0 / 0.0)".into()
        } else if v.is_infinite() {
            if v > 0.0 { "math.huge".into() } else { "(-math.huge)".into() }
        } else {
            format!("{:?}", v)
        }
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let place = self.place(member);
        if ty == Ty::Float { format!("({} + 0.0)", place) } else { place }
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let v = format!("pb_at({}, {})", self.place(member), index);
        if ty == Ty::Float { format!("({} + 0.0)", v) } else { v }
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let f = match (op, ty) {
            (AggOp::Sum, Ty::Float) => "pb_sumf",
            (AggOp::Product, Ty::Float) => "pb_prodf",
            (AggOp::Sum, _) => "pb_sum",
            (AggOp::Product, _) => "pb_prod",
        };
        format!("{}({})", f, self.place(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            return match op {
                ArithOp::Add => format!("({} + {})", a, b),
                ArithOp::Sub => format!("({} - {})", a, b),
                ArithOp::Mul => format!("({} * {})", a, b),
                ArithOp::Div => format!("pb_fdiv({}, {})", a, b),
                ArithOp::Pow => format!("({} ^ {})", a, b),
                _ => unreachable!("integer-only operator on floats"),
            };
        }
        match op {
            ArithOp::Add => format!("({} + {})", a, b),
            ArithOp::Sub => format!("({} - {})", a, b),
            ArithOp::Mul => format!("({} * {})", a, b),
            ArithOp::Div => format!("pb_div({}, {})", a, b),
            ArithOp::Pow => format!("pb_pow({}, {})", a, b),
            ArithOp::Mod => format!("pb_mod({}, {})", a, b),
            ArithOp::Shl => format!("pb_shl({}, {})", a, b),
            ArithOp::Shr => format!("pb_shr({}, {})", a, b),
            ArithOp::BitAnd => format!("({} & {})", a, b),
            ArithOp::BitOr => format!("({} | {})", a, b),
            ArithOp::BitXor => format!("({} ~ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, _ty: Ty) -> String {
        match op {
            UnaryOp::Neg => format!("(-{})", e),
            UnaryOp::BitNot => format!("(~{})", e),
            UnaryOp::Not => format!("(not {})", e),
        }
    }

    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        let sym = match op {
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Eq => "==",
            CmpOp::Ne => "~=",
        };
        format!("({} {} {})", a, sym, b)
    }

    fn logic(&self, op: crate::ir::LogicOp, a: String, b: String) -> String {
        let sym = if op == crate::ir::LogicOp::And { "and" } else { "or" };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("pb_if({}, {}, {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("pb_sqrt({})", args[0]),
            Func::Min => format!("math.min({}, {})", args[0], args[1]),
            Func::Max => format!("math.max({}, {})", args[0], args[1]),
        }
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("({} and 1 or 0)", e),
            (Ty::Bool, Ty::Float) => format!("({} and 1.0 or 0.0)", e),
            (Ty::Int, Ty::Float) => format!("({} + 0.0)", e),
            (Ty::Float, Ty::Int) => format!("pb_ftoi({})", e),
            (Ty::Int, Ty::Bool) => format!("({} ~= 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} ~= 0.0)", e),
            _ => e,
        }
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let v = match field {
            Some((_, f)) => format!("pb_last{}", super::naming::index(f)),
            None => "pb_last".into(),
        };
        if ty == Ty::Float { format!("({} + 0.0)", v) } else { v }
    }

    fn param(&self, index: usize) -> String {
        self.param_var(index)
    }

    fn len(&self, member: usize) -> String {
        format!("#{}", self.place(member))
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) // 8)", to, from)
    }

    fn stored(&self, member: usize) -> String {
        self.field(self.member(member))
    }

    fn remaining(&self) -> String {
        "r:remaining_bytes()".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("r:checksum({}, {}, {}, {}, {})", algo.id(), from, to, hf, ht)
    }
}

/// `expr` stored in a member of type `ty`: wrapped to its width.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } if *width < 64 => format!("pb_trunc({}, {}, {})", expr, width, signed),
        ValueType::Float { width: 32 } => format!("pb_f32({})", expr),
        _ => expr,
    }
}
