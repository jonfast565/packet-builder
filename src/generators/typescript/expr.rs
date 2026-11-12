//! TypeScript spelling of expressions: integers are signed 64-bit `bigint`s,
//! floats `number`s.

use super::naming::{TypeScript, ident, is_big, zero};
use crate::generators::common::{ExprLang, Mode, Scope, cmp_symbol};
use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, Ty, UnaryOp, ValueType};

/// A stored value of type `ty` as an i64 `bigint`.
pub fn to_i64(v: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width: 64, signed: false } => format!("BigInt.asIntN(64, {})", v),
        ValueType::Int { .. } if is_big(ty) => v,
        ValueType::Int { .. } => format!("BigInt({})", v),
        ValueType::Float { .. } => format!("pbFtoi({})", v),
        _ => v,
    }
}

/// A stored value of type `ty` as `ty_expr` (i64 `bigint` or f64 `number`).
fn view(v: String, ty: &ValueType, as_ty: Ty) -> String {
    match as_ty {
        Ty::Float if matches!(ty, ValueType::Float { .. }) => v,
        Ty::Float => format!("Number({})", v),
        Ty::Int => to_i64(v, ty),
        Ty::Bool => v,
    }
}

/// An i64 (or f64) expression converted to a stored value of type `ty`.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } if is_big(ty) => {
            format!("BigInt.as{}IntN({}, {})", if *signed { "" } else { "U" }, width, expr)
        }
        ValueType::Int { width, signed } => format!("pbTrunc({}, {}, {})", expr, width, signed),
        ValueType::Float { width: 32 } => format!("Math.fround({})", expr),
        _ => expr,
    }
}

impl ExprLang for Scope<'_, TypeScript> {
    fn int_lit(&self, v: i64) -> String {
        if v < 0 { format!("({}n)", v) } else { format!("{}n", v) }
    }

    fn float_lit(&self, v: f64) -> String {
        if v.is_nan() {
            "NaN".into()
        } else if v.is_infinite() {
            if v > 0.0 { "Infinity".into() } else { "(-Infinity)".into() }
        } else if v < 0.0 {
            format!("({:?})", v)
        } else {
            format!("{:?}", v)
        }
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let m = self.member(member);
        let place = self.place(member);
        if self.mode == Mode::Encode && m.is_derived() {
            // The encode-time local is an i64 already.
            return if ty == Ty::Float { format!("Number({})", place) } else { place };
        }
        view(place, &m.ty, ty)
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let m = self.member(member);
        view(format!("pbAt({}, {}, {})", self.place(member), index, zero(&m.ty)), &m.ty, ty)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let place = self.place(member);
        match (op, ty) {
            (AggOp::Sum, Ty::Float) => format!("pbSumF({})", place),
            (AggOp::Product, Ty::Float) => format!("pbProdF({})", place),
            (AggOp::Sum, _) => format!("pbSum({})", place),
            (AggOp::Product, _) => format!("pbProd({})", place),
        }
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            return match op {
                ArithOp::Add => format!("({} + {})", a, b),
                ArithOp::Sub => format!("({} - {})", a, b),
                ArithOp::Mul => format!("({} * {})", a, b),
                ArithOp::Div => format!("({} / {})", a, b),
                ArithOp::Pow => format!("pbFPow({}, {})", a, b),
                _ => unreachable!("integer-only operator on floats"),
            };
        }
        match op {
            ArithOp::Add => format!("pbW({} + {})", a, b),
            ArithOp::Sub => format!("pbW({} - {})", a, b),
            ArithOp::Mul => format!("pbW({} * {})", a, b),
            ArithOp::Div => format!("pbDiv({}, {})", a, b),
            ArithOp::Pow => format!("pbPow({}, {})", a, b),
            ArithOp::Mod => format!("pbMod({}, {})", a, b),
            ArithOp::Shl => format!("pbShl({}, {})", a, b),
            ArithOp::Shr => format!("pbShr({}, {})", a, b),
            ArithOp::BitAnd => format!("({} & {})", a, b),
            ArithOp::BitOr => format!("({} | {})", a, b),
            ArithOp::BitXor => format!("({} ^ {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("pbW(-{})", e),
            (UnaryOp::BitNot, _) => format!("(~{})", e),
            (UnaryOp::Not, _) => format!("(!{})", e),
        }
    }

    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        let sym = match op {
            CmpOp::Eq => "===",
            CmpOp::Ne => "!==",
            other => cmp_symbol(other),
        };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("({} ? {} : {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("Math.sqrt({})", args[0]),
            Func::Min => format!("pbMin({}, {})", args[0], args[1]),
            Func::Max => format!("pbMax({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        match self.member(member).ty {
            ValueType::Str => format!("BigInt(pbUtf8Len({}))", self.place(member)),
            _ => format!("BigInt({}.length)", self.place(member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("BigInt(Math.floor(({} - {}) / 8))", to, from)
    }

    fn stored(&self, member: usize) -> String {
        let m = self.member(member);
        to_i64(self.field(m), &m.ty)
    }

    fn version(&self) -> String {
        let latest = self.packet.version_bounds().1;
        match self.mode {
            Mode::Decode => format!("BigInt(pb_r.versionOr({}))", latest),
            Mode::Encode => format!("BigInt(pb_w.versionOr({}))", latest),
        }
    }

    fn remaining(&self) -> String {
        "BigInt(pb_r.remainingBytes())".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pb_w" } else { "pb_r" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("BigInt({}.checksum({}, {}, {}, {}, {}))", rw, algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let v = match field {
            Some((_, f)) => format!("pb_last.{}", ident(f)),
            None => "pb_last".into(),
        };
        match ty {
            Ty::Int => format!("pbI({})", v),
            Ty::Float => format!("Number({})", v),
            Ty::Bool => v,
        }
    }

    fn param(&self, index: usize) -> String {
        to_i64(self.param_var(index), &self.packet.params[index].ty)
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("({} ? 1n : 0n)", e),
            (Ty::Bool, Ty::Float) => format!("({} ? 1 : 0)", e),
            (Ty::Int, Ty::Float) => format!("Number({})", e),
            (Ty::Float, Ty::Int) => format!("pbFtoi({})", e),
            (Ty::Int, Ty::Bool) => format!("({} !== 0n)", e),
            (Ty::Float, Ty::Bool) => format!("({} !== 0)", e),
            _ => e,
        }
    }
}
