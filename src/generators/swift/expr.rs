//! Swift spelling of expressions. Integer expressions are `Int64`, float
//! expressions `Double`; every operator that can overflow wraps, and the
//! runtime's helpers (`pbDiv`, `pbShl`, ...) never trap.

use super::naming::{Swift, ident, scalar_type};
use crate::generators::common::Mode;
use crate::generators::common::{ExprLang, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, Func, Ty, UnaryOp, ValueType, storage_for};

impl ExprLang for Scope<'_, Swift> {
    fn int_lit(&self, v: i64) -> String {
        if v == i64::MIN { "Int64.min".into() } else { format!("({} as Int64)", v) }
    }

    fn float_lit(&self, v: f64) -> String {
        if v.is_nan() {
            "Double.nan".into()
        } else if v.is_infinite() {
            if v > 0.0 { "Double.infinity".into() } else { "(-Double.infinity)".into() }
        } else {
            format!("({:?} as Double)", v)
        }
    }

    fn param(&self, index: usize) -> String {
        format!("pbI({})", self.param_var(index))
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        let f = if ty == Ty::Float { "pbF" } else { "pbI" };
        format!("{}({})", f, self.place(member))
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let f = if ty == Ty::Float { "pbIdxF" } else { "pbIdxI" };
        format!("{}({}, {})", f, self.place(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let f = match (op, ty) {
            (AggOp::Sum, Ty::Float) => "pbSumF",
            (AggOp::Product, Ty::Float) => "pbProductF",
            (AggOp::Sum, _) => "pbSumI",
            (AggOp::Product, _) => "pbProductI",
        };
        format!("{}({})", f, self.place(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            return match op {
                ArithOp::Add => format!("({} + {})", a, b),
                ArithOp::Sub => format!("({} - {})", a, b),
                ArithOp::Mul => format!("({} * {})", a, b),
                ArithOp::Div => format!("({} / {})", a, b),
                ArithOp::Pow => format!("pbPowF({}, {})", a, b),
                _ => unreachable!("integer-only operator on floats"),
            };
        }
        match op {
            ArithOp::Add => format!("({} &+ {})", a, b),
            ArithOp::Sub => format!("({} &- {})", a, b),
            ArithOp::Mul => format!("({} &* {})", a, b),
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
            (UnaryOp::Neg, _) => format!("(0 &- {})", e),
            (UnaryOp::BitNot, _) => format!("(~{})", e),
            (UnaryOp::Not, _) => format!("(!{})", e),
        }
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("({} ? {} : {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, _ty: Ty) -> String {
        match func {
            Func::Sqrt => format!("{}.squareRoot()", args[0]),
            Func::Min => format!("Swift.min({}, {})", args[0], args[1]),
            Func::Max => format!("Swift.max({}, {})", args[0], args[1]),
        }
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let f = if ty == Ty::Float { "pbF" } else { "pbI" };
        match field {
            Some((_, name)) => format!("{}(pb_last.{})", f, ident(name)),
            None => format!("{}(pb_last)", f),
        }
    }

    fn len(&self, member: usize) -> String {
        if self.member(member).ty == ValueType::Str && self.member(member).array.is_none() {
            format!("Int64({}.utf8.count)", self.place(member))
        } else {
            format!("Int64({}.count)", self.place(member))
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("Int64(({} - {}) / 8)", to, from)
    }

    fn stored(&self, member: usize) -> String {
        format!("pbI({})", self.field(self.member(member)))
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
        format!("pbI({}.checksum({}, {}, {}, {}, {}))", rw, algo.id(), from, to, hf, ht)
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("pbB2I({})", e),
            (Ty::Bool, Ty::Float) => format!("Double(pbB2I({}))", e),
            (Ty::Int, Ty::Float) => format!("Double({})", e),
            (Ty::Float, Ty::Int) => format!("pbF2I({})", e),
            (Ty::Int, Ty::Bool) => format!("({} != 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} != 0.0)", e),
            _ => e,
        }
    }
}

/// Convert an Int64/Double expression to a member's storage type, wrapping
/// like the other backends.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            let st = scalar_type(ty);
            if *width == storage_for(*width) {
                format!("{}(truncatingIfNeeded: {})", st, expr)
            } else {
                format!("{}(truncatingIfNeeded: pbTrunc({}, {}, {}))", st, expr, width, signed)
            }
        }
        ValueType::Float { .. } => format!("{}({})", scalar_type(ty), expr),
        _ => expr,
    }
}

/// `!cond`, parenthesised unless `cond` is one parenthesised group
/// already (Swift rejects `!!x`).
pub fn negate(cond: String) -> String {
    if wrapped(&cond) { format!("!{}", cond) } else { format!("!({})", cond) }
}

/// Whether `s` is `( ... )` with the first parenthesis closing at the end.
fn wrapped(s: &str) -> bool {
    if !s.starts_with('(') {
        return false;
    }
    let mut depth = 0;
    let mut in_str = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '(' if !in_str => depth += 1,
            ')' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return i == s.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}
