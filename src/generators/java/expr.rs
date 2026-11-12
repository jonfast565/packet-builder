//! Java spelling of expressions. Integer expressions are `long` (wrapping),
//! floats `double`.

use super::naming::{Java, field_name, scalar_type};
use crate::generators::common::Mode;
use crate::generators::common::{ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, Func, Ty, UnaryOp, ValueType, storage_for};

fn num(ty: Ty) -> &'static str {
    if ty == Ty::Float { "double" } else { "long" }
}

impl ExprLang for Scope<'_, Java> {
    fn int_lit(&self, v: i64) -> String {
        format!("({}L)", v)
    }

    fn float_lit(&self, v: f64) -> String {
        if v.is_nan() {
            "Double.NaN".into()
        } else if v.is_infinite() {
            if v > 0.0 { "Double.POSITIVE_INFINITY".into() } else { "Double.NEGATIVE_INFINITY".into() }
        } else {
            format!("({:?}d)", v)
        }
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        format!("(({}){})", num(ty), self.place(member))
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let at = if self.member(member).ty.is_byte() { "atU8" } else { "at" };
        format!("(({})Pb.{}({}, {}))", num(ty), at, self.place(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let f = match op {
            AggOp::Sum => "sum",
            AggOp::Product => "product",
        };
        let u8s = if self.member(member).ty.is_byte() { "U8" } else { "" };
        format!("(({})Pb.{}{}({}))", num(ty), f, u8s, self.place(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        match (op, ty) {
            (ArithOp::Add, _) => format!("({} + {})", a, b),
            (ArithOp::Sub, _) => format!("({} - {})", a, b),
            (ArithOp::Mul, _) => format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => format!("({} / {})", a, b),
            (ArithOp::Div, _) => format!("Pb.div({}, {})", a, b),
            (ArithOp::Pow, Ty::Float) => format!("Math.pow({}, {})", a, b),
            (ArithOp::Pow, _) => format!("Pb.pow({}, {})", a, b),
            (ArithOp::Mod, _) => format!("Pb.mod({}, {})", a, b),
            (ArithOp::Shl, _) => format!("Pb.shl({}, {})", a, b),
            (ArithOp::Shr, _) => format!("Pb.shr({}, {})", a, b),
            (ArithOp::BitAnd, _) => format!("({} & {})", a, b),
            (ArithOp::BitOr, _) => format!("({} | {})", a, b),
            (ArithOp::BitXor, _) => format!("({} ^ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, _ty: Ty) -> String {
        match op {
            UnaryOp::Neg => format!("(-{})", e),
            UnaryOp::BitNot => format!("(~{})", e),
            UnaryOp::Not => format!("(!{})", e),
        }
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("({} ? {} : {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("Math.sqrt({})", args[0]),
            Func::Min => format!("Math.min({}, {})", args[0], args[1]),
            Func::Max => format!("Math.max({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        let m = self.member(member);
        match m.ty {
            ValueType::Str => format!("((long)Pb.utf8Len({}))", self.place(member)),
            _ if m.ty.is_byte() => format!("((long)Pb.len({}))", self.place(member)),
            _ => format!("((long){}.length)", self.place(member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) / 8)", to, from)
    }

    fn stored(&self, member: usize) -> String {
        format!("((long){})", self.field(self.member(member)))
    }

    fn version(&self) -> String {
        let latest = self.packet.version_bounds().1;
        match self.mode {
            Mode::Decode => format!("pbR.versionOr({})", latest),
            Mode::Encode => format!("pbW.versionOr({})", latest),
        }
    }

    fn remaining(&self) -> String {
        "pbR.remainingBytes()".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pbW" } else { "pbR" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("{}.checksum({}, {}, {}, {}, {})", rw, algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        match field {
            Some((_, f)) => format!("(({})pbLast.{})", num(ty), field_name(f)),
            None => format!("(({})pbLast)", num(ty)),
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
            (Ty::Float, Ty::Int) => format!("Pb.ftoi({})", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0L)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0.0d)", e),
            _ => e,
        }
    }
}

/// Convert a long/double expression to a member's Java type: a narrowing
/// cast wraps, and values narrower than their type are cut to their width.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    match ty {
        ValueType::Int { width, signed } if (*signed && *width == storage_for(*width)) || *width == 64 => {
            format!("(({})({}))", st, expr)
        }
        ValueType::Int { width, signed } => format!("(({})Pb.trunc({}, {}, {}))", st, expr, width, signed),
        _ => format!("(({})({}))", st, expr),
    }
}
