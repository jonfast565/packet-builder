//! Fortran spelling of expressions. Integer expressions are int64, float
//! expressions real64. Integer arithmetic goes through runtime functions
//! that wrap instead of overflowing, which also keeps the compiler from
//! folding (and rejecting) constant expressions that overflow.

use super::naming::{Fortran, component, int_kind, real_kind};
use crate::generators::common::union::held_arm;
use crate::generators::common::{ExprLang, Mode, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, LogicOp, Ty, UnaryOp, ValueType};

impl Scope<'_, Fortran> {
    /// The reader or writer expressions run against.
    fn stream(&self) -> &'static str {
        if self.mode == Mode::Encode { "pb_w" } else { "pb_r" }
    }
}

/// An int64 literal.
pub fn int64(v: i64) -> String {
    if v == i64::MIN {
        "PB_MIN64".into()
    } else if v < 0 {
        format!("(-{}_int64)", -v)
    } else {
        format!("{}_int64", v)
    }
}

impl ExprLang for Scope<'_, Fortran> {
    fn int_lit(&self, v: i64) -> String {
        int64(v)
    }

    fn float_lit(&self, v: f64) -> String {
        if v.is_nan() {
            "ieee_value(0.0_real64, ieee_quiet_nan)".into()
        } else if v.is_infinite() {
            let which = if v > 0.0 { "ieee_positive_inf" } else { "ieee_negative_inf" };
            format!("ieee_value(0.0_real64, {})", which)
        } else if v < 0.0 {
            format!("(-{:e}_real64)", -v)
        } else {
            format!("{:e}_real64", v)
        }
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        if ty == Ty::Float {
            format!("real({}, real64)", self.place(member))
        } else {
            format!("int({}, int64)", self.place(member))
        }
    }

    fn index(&self, member: usize, index: String, _ty: Ty) -> String {
        let f = if self.member(member).ty.is_byte() { "pb_elem_u8" } else { "pb_elem" };
        format!("{}({}, {})", f, self.place(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, _ty: Ty) -> String {
        let f = if op == AggOp::Sum { "pb_sum" } else { "pb_product" };
        let u8 = if self.member(member).ty.is_byte() { "_u8" } else { "" };
        format!("{}{}({})", f, u8, self.place(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        match (op, ty) {
            (ArithOp::Add, Ty::Float) => format!("({} + {})", a, b),
            (ArithOp::Sub, Ty::Float) => format!("({} - {})", a, b),
            (ArithOp::Mul, Ty::Float) => format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => format!("pb_fdiv({}, {})", a, b),
            (ArithOp::Pow, Ty::Float) => format!("pb_powf({}, {})", a, b),
            (ArithOp::Mod, Ty::Float) => format!("mod({}, {})", a, b),
            (ArithOp::Add, _) => format!("pb_add({}, {})", a, b),
            (ArithOp::Sub, _) => format!("pb_subt({}, {})", a, b),
            (ArithOp::Mul, _) => format!("pb_mul({}, {})", a, b),
            (ArithOp::Div, _) => format!("pb_div({}, {})", a, b),
            (ArithOp::Pow, _) => format!("pb_pow({}, {})", a, b),
            (ArithOp::Mod, _) => format!("pb_mod({}, {})", a, b),
            (ArithOp::Shl, _) => format!("pb_shl({}, {})", a, b),
            (ArithOp::Shr, _) => format!("pb_shr({}, {})", a, b),
            (ArithOp::BitAnd, _) => format!("iand({}, {})", a, b),
            (ArithOp::BitOr, _) => format!("ior({}, {})", a, b),
            (ArithOp::BitXor, _) => format!("ieor({}, {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("pb_neg({})", e),
            (UnaryOp::BitNot, _) => format!("not({})", e),
            (UnaryOp::Not, _) => format!("(.not. {})", e),
        }
    }

    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        let sym = match op {
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Eq => "==",
            CmpOp::Ne => "/=",
        };
        format!("({} {} {})", a, sym, b)
    }

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { ".and." } else { ".or." };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("merge({}, {}, {})", then, other, cond)
    }

    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String {
        match (func, ty) {
            (Func::Sqrt, _) => format!("pb_sqrt({})", args[0]),
            (Func::Min, Ty::Float) => format!("pb_minf({}, {})", args[0], args[1]),
            (Func::Max, Ty::Float) => format!("pb_maxf({}, {})", args[0], args[1]),
            (Func::Min, _) => format!("min({}, {})", args[0], args[1]),
            (Func::Max, _) => format!("max({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        match self.member(member).ty {
            ValueType::Str if self.member(member).array.is_none() => format!("pb_strlen({})", self.place(member)),
            _ => format!("pb_size({})", self.place(member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) / 8_int64)", to, from)
    }

    fn stored(&self, member: usize) -> String {
        format!("int({}, int64)", self.field(self.member(member)))
    }

    fn holds(&self, member: usize, arm: &str) -> String {
        let (k, _) = held_arm(self.packet, member, arm);
        format!("({}%pb_arm == {})", self.field(self.member(member)), k + 1)
    }

    fn version(&self) -> String {
        let latest = self.packet.version_bounds().1;
        format!("pb_version_or({}, {})", self.stream(), latest)
    }

    fn remaining(&self) -> String {
        "pb_remaining_bytes(pb_r)".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let (hf, ht) = hole.unwrap_or(("0_int64", "0_int64"));
        let f = if self.mode == Mode::Encode { "pb_writer_checksum" } else { "pb_reader_checksum" };
        format!("{}({}, {}, {}, {}, {}, {})", f, self.stream(), algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        match (field, ty) {
            (Some((packet, f)), Ty::Float) => format!("real({}%{}, real64)", last_var(Some(packet), ty), component(f)),
            (Some((packet, f)), _) => format!("int({}%{}, int64)", last_var(Some(packet), ty), component(f)),
            (None, _) => last_var(None, ty),
        }
    }

    fn param(&self, index: usize) -> String {
        format!("int({}, int64)", self.param_var(index))
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("merge(1_int64, 0_int64, {})", e),
            (Ty::Bool, Ty::Float) => format!("merge(1.0_real64, 0.0_real64, {})", e),
            (Ty::Int, Ty::Float) => format!("real({}, real64)", e),
            (Ty::Float, Ty::Int) => format!("pb_ftoi({})", e),
            (Ty::Int, Ty::Bool) => format!("({} /= 0_int64)", e),
            (Ty::Float, Ty::Bool) => format!("({} /= 0.0_real64)", e),
            _ => e,
        }
    }
}

/// The local holding the element an `until` condition looks at: a copy
/// of the element packet (`pblast_Link`), or a number as int64 or real64.
pub fn last_var(packet: Option<&str>, ty: Ty) -> String {
    match (packet, ty) {
        (Some(p), _) => format!("pblast_{}", p),
        (None, Ty::Float) => "pblastf".into(),
        (None, _) => "pblasti".into(),
    }
}

/// Convert an int64/real64 expression to a member's storage: integers are
/// cut to their width first, so the conversion never overflows.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width: 64, .. } => expr,
        ValueType::Int { width, signed } => {
            format!(
                "int(pb_trunc({}, {}, {}), {})",
                expr,
                width,
                if *signed { ".true." } else { ".false." },
                int_kind(*width, *signed)
            )
        }
        ValueType::Float { width } => format!("real({}, {})", expr, real_kind(*width)),
        _ => expr,
    }
}
