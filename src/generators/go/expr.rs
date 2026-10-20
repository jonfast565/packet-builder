//! Go spelling of expressions.

use super::naming::{Go, scalar_type};
use crate::generators::common::{ExprLang, Mode, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, Func, TExpr, Ty, UnaryOp, ValueType, storage_for};

impl ExprLang for Scope<'_, Go> {
    fn int_lit(&self, v: i64) -> String {
        format!("int64({})", v)
    }

    fn float_lit(&self, v: f64) -> String {
        format!("float64({:?})", v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let t = if ty == Ty::Float { "float64" } else { "int64" };
        format!("{}({})", t, self.place(member))
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let t = if ty == Ty::Float { "float64" } else { "int64" };
        format!("{}(pbAt({}, {}))", t, self.place(member), index)
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
            (ArithOp::Add, _) => format!("({} + {})", a, b),
            (ArithOp::Sub, _) => format!("({} - {})", a, b),
            (ArithOp::Mul, _) => format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => format!("pbFDiv({}, {})", a, b),
            (ArithOp::Div, _) => format!("pbDiv({}, {})", a, b),
            (ArithOp::Pow, Ty::Float) => format!("math.Pow({}, {})", a, b),
            (ArithOp::Pow, _) => format!("pbPow({}, {})", a, b),
            (ArithOp::Mod, _) => format!("pbMod({}, {})", a, b),
            (ArithOp::Shl, _) => format!("pbShl({}, {})", a, b),
            (ArithOp::Shr, _) => format!("pbShr({}, {})", a, b),
            (ArithOp::BitAnd, _) => format!("({} & {})", a, b),
            (ArithOp::BitOr, _) => format!("({} | {})", a, b),
            (ArithOp::BitXor, _) => format!("({} ^ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, _ty: Ty) -> String {
        match op {
            UnaryOp::Neg => format!("(-{})", e),
            UnaryOp::BitNot => format!("(^{})", e),
            UnaryOp::Not => format!("(!{})", e),
        }
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("pbIf({}, {}, {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("math.Sqrt({})", args[0]),
            Func::Min => format!("pbMin({}, {})", args[0], args[1]),
            Func::Max => format!("pbMax({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        format!("int64(len({}))", self.place(member))
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("pbSize({}, {})", from, to)
    }

    fn stored(&self, member: usize) -> String {
        format!("int64({})", self.field(self.member(member)))
    }

    fn remaining(&self) -> String {
        "pbR.RemainingBytes()".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pbW" } else { "pbR" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("int64({}.Checksum({}, {}, {}, {}, {}))", rw, algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let t = if ty == Ty::Float { "float64" } else { "int64" };
        match field {
            Some((_, f)) => format!("{}(pbLast.{})", t, super::naming::field_name(f)),
            None => format!("{}(pbLast)", t),
        }
    }

    fn param(&self, index: usize) -> String {
        format!("int64({})", self.param_var(index))
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("pbB2I({})", e),
            (Ty::Bool, Ty::Float) => format!("float64(pbB2I({}))", e),
            (Ty::Int, Ty::Float) => format!("float64({})", e),
            (Ty::Float, Ty::Int) => format!("int64({})", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0)", e),
            _ => e,
        }
    }
}

/// Convert an int64/float64 expression to a member's storage type. Constant
/// expressions go through pbVal so that Go does not reject overflowing
/// constant conversions at compile time.
pub fn store_value(expr: &TExpr, code: String, ty: &ValueType) -> String {
    let mut deps = Vec::new();
    expr.deps(&mut deps);
    let code = if deps.is_empty() { format!("pbVal({})", code) } else { code };
    match ty {
        ValueType::Int { width, signed } => {
            let st = scalar_type(ty);
            if *width == storage_for(*width) {
                format!("{}({})", st, code)
            } else {
                format!("{}(pbTrunc({}, {}, {}))", st, code, width, signed)
            }
        }
        _ => format!("{}({})", scalar_type(ty), code),
    }
}
