//! Object Pascal spelling of expressions. Integer expressions are Int64,
//! float expressions Double; the unit turns overflow and range checks off,
//! so integer arithmetic wraps.

use super::naming::{Pascal, ident, scalar_type};
use crate::generators::common::{ExprLang, Mode, Scope};
use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, LogicOp, Ty, UnaryOp, ValueType, storage_for};

impl ExprLang for Scope<'_, Pascal> {
    fn int_lit(&self, v: i64) -> String {
        if v == i64::MIN { "Low(Int64)".into() } else { format!("Int64({})", v) }
    }

    fn float_lit(&self, v: f64) -> String {
        format!("({:?})", v)
    }

    fn member_ref(&self, member: usize, ty: Ty) -> String {
        if ty == Ty::Float { format!("({})", self.place(member)) } else { format!("Int64({})", self.place(member)) }
    }

    fn index(&self, member: usize, index: String, _ty: Ty) -> String {
        format!("PbAt({}, {})", self.place(member), index)
    }

    fn aggregate(&self, member: usize, op: AggOp, _ty: Ty) -> String {
        let f = if op == AggOp::Sum { "PbSum" } else { "PbProduct" };
        format!("{}({})", f, self.place(member))
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        match (op, ty) {
            (ArithOp::Add, _) => format!("({} + {})", a, b),
            (ArithOp::Sub, _) => format!("({} - {})", a, b),
            (ArithOp::Mul, _) => format!("({} * {})", a, b),
            (ArithOp::Div, Ty::Float) => format!("({} / {})", a, b),
            (ArithOp::Div, _) => format!("PbDiv({}, {})", a, b),
            (ArithOp::Pow, Ty::Float) => format!("PbPowF({}, {})", a, b),
            (ArithOp::Pow, _) => format!("PbPow({}, {})", a, b),
            (ArithOp::Mod, _) => format!("PbMod({}, {})", a, b),
            (ArithOp::Shl, _) => format!("PbShl({}, {})", a, b),
            (ArithOp::Shr, _) => format!("PbShr({}, {})", a, b),
            (ArithOp::BitAnd, _) => format!("({} and {})", a, b),
            (ArithOp::BitOr, _) => format!("({} or {})", a, b),
            (ArithOp::BitXor, _) => format!("({} xor {})", a, b),
        }
    }

    fn unary(&self, op: UnaryOp, e: String, _ty: Ty) -> String {
        match op {
            UnaryOp::Neg => format!("(-{})", e),
            UnaryOp::BitNot | UnaryOp::Not => format!("(not {})", e),
        }
    }

    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        let sym = match op {
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Eq => "=",
            CmpOp::Ne => "<>",
        };
        format!("({} {} {})", a, sym, b)
    }

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "and" } else { "or" };
        format!("({} {} {})", a, sym, b)
    }

    fn guard(&self, cond: String, then: String, other: String, ty: Ty) -> String {
        let f = match ty {
            Ty::Float => "PbIfF",
            Ty::Bool => "PbIfB",
            Ty::Int => "PbIfI",
        };
        format!("{}({}, {}, {})", f, cond, then, other)
    }

    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String {
        let suffix = if ty == Ty::Float { "F" } else { "I" };
        match func {
            Func::Sqrt => format!("PbSqrt({})", args[0]),
            Func::Min => format!("PbMin{}({}, {})", suffix, args[0], args[1]),
            Func::Max => format!("PbMax{}({}, {})", suffix, args[0], args[1]),
        }
    }

    fn len(&self, member: usize) -> String {
        match self.member(member).ty {
            ValueType::Str => format!("PbUtf8Len({})", self.place(member)),
            _ => format!("Int64(Length({}))", self.place(member)),
        }
    }

    fn size(&self, from: &str, to: &str) -> String {
        format!("(({} - {}) div 8)", to, from)
    }

    fn stored(&self, member: usize) -> String {
        format!("Int64({})", self.field(self.member(member)))
    }

    fn version(&self) -> String {
        let latest = self.packet.version_bounds().1;
        match self.mode {
            Mode::Decode => format!("pbR.VersionOr({})", latest),
            Mode::Encode => format!("pbW.VersionOr({})", latest),
        }
    }

    fn remaining(&self) -> String {
        "pbR.RemainingBytes".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let rw = if self.mode == Mode::Encode { "pbW" } else { "pbR" };
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("Int64({}.Checksum({}, {}, {}, {}, {}))", rw, algo.id(), from, to, hf, ht)
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        match (field, ty) {
            (Some((packet, f)), Ty::Float) => format!("({}.{})", last_var(Some(packet), ty), ident(f)),
            (Some((packet, f)), _) => format!("Int64({}.{})", last_var(Some(packet), ty), ident(f)),
            (None, _) => last_var(None, ty),
        }
    }

    fn param(&self, index: usize) -> String {
        format!("Int64({})", self.param_var(index))
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool, Ty::Int) => format!("Int64(Ord({}))", e),
            (Ty::Bool, Ty::Float) => format!("PbItoF(Ord({}))", e),
            (Ty::Int, Ty::Float) => format!("PbItoF({})", e),
            (Ty::Float, Ty::Int) => format!("PbFtoI({})", e),
            (Ty::Int, Ty::Bool) => format!("({} <> 0)", e),
            (Ty::Float, Ty::Bool) => format!("({} <> 0.0)", e),
            _ => e,
        }
    }
}

/// The local holding the element an `until` condition looks at: the
/// element packet (`pbLast_Link`), or a number as Int64 or Double.
pub fn last_var(packet: Option<&str>, ty: Ty) -> String {
    match (packet, ty) {
        (Some(p), _) => format!("pbLast_{}", p),
        (None, Ty::Float) => "pbLastF".into(),
        (None, _) => "pbLastI".into(),
    }
}

/// Convert an Int64/Double expression to a member's storage type: a value
/// typecast truncates (range checks are off); floats convert on assignment.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            let st = scalar_type(ty);
            if *width == storage_for(*width) {
                format!("{}({})", st, expr)
            } else {
                format!("{}(PbTrunc({}, {}, {}))", st, expr, width, if *signed { "True" } else { "False" })
            }
        }
        _ => expr,
    }
}
