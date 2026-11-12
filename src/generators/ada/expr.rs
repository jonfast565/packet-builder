//! Ada spelling of expressions. Integer expressions are Integer_64 and go
//! through the runtime's wrapping helpers (`Pb_Add`, ...), so they never
//! overflow; float expressions are IEEE_Float_64.

use super::naming::{Ada, calc_var, ident, param_var, type_name};
use crate::generators::common::{Dialect, ExprLang, Mode, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, LogicOp, Ty, UnaryOp, ValueType, storage_for};

/// Where an expression reads `member`: calculated and derived members are
/// the `Pbc_` locals while encoding (see `Scope::place`).
pub fn place(scope: &Scope<'_, Ada>, member: usize) -> String {
    let m = scope.member(member);
    if scope.mode == Mode::Encode && ((m.is_calculated() && !m.is_decode_only()) || m.is_derived()) {
        calc_var(&m.name)
    } else {
        Ada::field(scope.packet, m)
    }
}

/// The reader or writer of the scope.
fn rw(scope: &Scope<'_, Ada>) -> &'static str {
    if scope.mode == Mode::Encode { "W" } else { "R" }
}

/// `IEEE_Float_64'(1.5E-7)`: Ada wants a digit on both sides of the point.
pub fn float_literal(v: f64) -> String {
    if v.is_nan() {
        return "Pb_NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Pb_Inf".into() } else { "Pb_NInf".into() };
    }
    let text = format!("{:e}", v);
    let (mantissa, exp) = text.split_once('e').unwrap_or((&text, "0"));
    let mantissa = if mantissa.contains('.') { mantissa.to_string() } else { format!("{}.0", mantissa) };
    format!("IEEE_Float_64'({}E{})", mantissa, exp)
}

impl ExprLang for Scope<'_, Ada> {
    fn int_lit(&self, v: i64) -> String {
        if v == i64::MIN { "Integer_64'First".into() } else { format!("Integer_64'({})", v) }
    }

    fn float_lit(&self, v: f64) -> String {
        float_literal(v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        if ty == Ty::Float {
            format!("Pb_F ({})", place(self, member))
        } else {
            format!("Pb_I ({})", place(self, member))
        }
    }

    fn index(&self, member: usize, index: String, _ty: Ty) -> String {
        format!("Pb_Elem ({}, {})", place(self, member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, _ty: Ty) -> String {
        let f = if op == AggOp::Sum { "Pb_Sum" } else { "Pb_Product" };
        format!("{} ({})", f, place(self, member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        let f = match (op, ty) {
            (ArithOp::Add, Ty::Float) => return format!("({} + {})", a, b),
            (ArithOp::Sub, Ty::Float) => return format!("({} - {})", a, b),
            (ArithOp::Mul, Ty::Float) => return format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => "Pb_Div_F",
            (ArithOp::Pow, Ty::Float) => "Pb_Pow_F",
            (ArithOp::Add, _) => "Pb_Add",
            (ArithOp::Sub, _) => "Pb_Minus",
            (ArithOp::Mul, _) => "Pb_Mul",
            (ArithOp::Div, _) => "Pb_Div",
            (ArithOp::Pow, _) => "Pb_Pow",
            (ArithOp::Mod, _) => "Pb_Rem",
            (ArithOp::Shl, _) => "Pb_Shl",
            (ArithOp::Shr, _) => "Pb_Shr",
            (ArithOp::BitAnd, _) => "Pb_And",
            (ArithOp::BitOr, _) => "Pb_Or",
            (ArithOp::BitXor, _) => "Pb_Xor",
        };
        format!("{} ({}, {})", f, a, b)
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Neg, Ty::Float) => format!("(-{})", e),
            (UnaryOp::Neg, _) => format!("Pb_Neg ({})", e),
            (UnaryOp::BitNot, _) => format!("Pb_Not ({})", e),
            (UnaryOp::Not, _) => format!("(not {})", e),
        }
    }

    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        let sym = match op {
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Eq => "=",
            CmpOp::Ne => "/=",
        };
        format!("({} {} {})", a, sym, b)
    }

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "and then" } else { "or else" };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, _ty: Ty) -> String {
        format!("(if {} then {} else {})", cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String {
        match (func, ty) {
            (Func::Sqrt, _) => format!("Pb_Sqrt ({})", args[0]),
            (Func::Min, Ty::Float) => format!("Pb_Min_F ({}, {})", args[0], args[1]),
            (Func::Max, Ty::Float) => format!("Pb_Max_F ({}, {})", args[0], args[1]),
            (Func::Min, _) => format!("Integer_64'Min ({}, {})", args[0], args[1]),
            (Func::Max, _) => format!("Integer_64'Max ({}, {})", args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        match self.member(member).ty {
            ValueType::Str if self.member(member).array.is_none() => {
                format!("Integer_64 (Pb_SU.Length ({}))", place(self, member))
            }
            ValueType::Mac if self.member(member).array.is_none() => "Integer_64'(6)".into(),
            _ => format!("Integer_64 ({}.Length)", place(self, member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) / 8)", to, from)
    }

    fn stored(&self, member: usize) -> String {
        format!("Pb_I ({})", self.field(self.member(member)))
    }

    fn version(&self) -> String {
        let latest = self.packet.version_bounds().1;
        format!("Pb_Version_Or ({}.T, {})", rw(self), latest)
    }

    fn remaining(&self) -> String {
        "Pb_Remaining_Bytes (R)".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("Pb_U2I (Pb_Checksum ({}, {}, {}, {}, {}, {}))", rw(self), algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let conv = if ty == Ty::Float { "Pb_F" } else { "Pb_I" };
        match field {
            Some((packet, f)) => format!("{} ({}.{})", conv, last_var(Some(packet), ty), ident(f)),
            None => last_var(None, ty),
        }
    }

    fn param(&self, index: usize) -> String {
        let p = &self.packet.params[index];
        let conv = if matches!(p.ty, ValueType::Float { .. }) { "Pb_F" } else { "Pb_I" };
        format!("{} ({})", conv, param_var(&p.name))
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("(if {} then Integer_64'(1) else Integer_64'(0))", e),
            (Ty::Bool, Ty::Float) => format!("(if {} then IEEE_Float_64'(1.0) else IEEE_Float_64'(0.0))", e),
            (Ty::Int, Ty::Float) => format!("IEEE_Float_64 ({})", e),
            (Ty::Float, Ty::Int) => format!("Pb_Ftoi ({})", e),
            (Ty::Int, Ty::Bool) => format!("({} /= 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} /= 0.0)", e),
            _ => e,
        }
    }
}

/// The local holding the element an `until` condition looks at: the
/// element packet (`Pb_Last_Link`), or a number as Integer_64 or
/// IEEE_Float_64.
pub fn last_var(packet: Option<&str>, ty: Ty) -> String {
    match (packet, ty) {
        (Some(p), _) => format!("Pb_Last_{}", type_name(p)),
        (None, Ty::Float) => "Pb_Last_F".into(),
        (None, _) => "Pb_Last_I".into(),
    }
}

/// Convert an Integer_64 / IEEE_Float_64 expression to a member's storage
/// type: integers are cut to the member's width (never a range error),
/// floats narrowed without a range check.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed: false } => {
            let cut = format!("Pb_Trunc_U ({}, {})", expr, width);
            match storage_for(*width) {
                64 => cut,
                s => format!("Pb_To_U{} ({})", s, cut),
            }
        }
        ValueType::Int { width, signed: true } => match storage_for(*width) {
            64 => format!("Pb_Trunc ({}, {}, True)", expr, width),
            s if s == *width => format!("Pb_To_I{} ({})", s, expr),
            s => format!("Pb_To_I{} (Pb_Trunc ({}, {}, True))", s, expr, width),
        },
        ValueType::Float { width: 32 } => format!("Pb_To_F32 ({})", expr),
        _ => expr,
    }
}
