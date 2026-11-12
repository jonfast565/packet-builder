//! Pieces shared by the two Lua generators, the codec backend
//! (`generators::lua`) and the Wireshark dissector (`generators::wireshark`):
//! identifiers, literals, the expression spelling (one [`ExprLang`] for every
//! [`LuaDialect`]) and the runtime core both paste in.
//!
//! Lua 5.3+ integers are 64-bit and wrap, which is exactly the semantics
//! every runtime implements; a uint64 is held as its bit pattern.

use super::dialect::{Dialect, Scope};
use super::expr::{ExprLang, Mode};
use crate::ir::{AggOp, ArithOp, Checksum, CmpOp, Func, LogicOp, Ty, UnaryOp, ValueType};

const KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "global", "goto", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// True for Lua's reserved words (`global` is one from Lua 5.5 on).
pub fn is_keyword(name: &str) -> bool {
    KEYWORDS.contains(&name)
}

/// `.name`, or `["name"]` for a Lua keyword: indexing a table by `name`.
pub fn index(name: &str) -> String {
    if is_keyword(name) { format!("[\"{}\"]", name) } else { format!(".{}", name) }
}

/// A Lua string literal holding these bytes (`"\x0d\x0a"`).
pub fn byte_string(bytes: &[u8]) -> String {
    let items: String = bytes.iter().map(|b| format!("\\x{:02x}", b)).collect();
    format!("\"{}\"", items)
}

/// `expr` stored in a member of type `ty`: wrapped to its width.
pub fn store_value(expr: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } if *width < 64 => format!("pb_trunc({}, {}, {})", expr, width, signed),
        ValueType::Float { width: 32 } => format!("pb_f32({})", expr),
        _ => expr,
    }
}

/// The runtime core shared by both Lua runtimes (reader, checksums,
/// expression helpers), pasted where a runtime has its `-- @lua_core` line.
const CORE: &str = include_str!("../../../runtime/lua_core.lua");

/// A Lua runtime's source with the core in place of its `-- @lua_core`
/// line, then trimmed to the module's needs (`super::runtime_source`).
pub fn runtime(text: &str, versioned: bool) -> String {
    let full = text.replacen("-- @lua_core\n", CORE, 1);
    super::runtime_source(&full, versioned)
}

/// What differs between the Lua generators' expressions.
pub trait LuaDialect: Dialect {
    /// Convert uint64 values to floats exactly (`pb_u2f`) rather than as
    /// their signed bit pattern.
    const EXACT_U64: bool = false;
}

fn is_u64(ty: &ValueType) -> bool {
    matches!(ty, ValueType::Int { width: 64, signed: false })
}

impl<D: LuaDialect> Scope<'_, D> {
    /// `v`, a value of member `member`'s element type, as a float.
    fn float_of(&self, v: String, member: usize) -> String {
        if D::EXACT_U64 && is_u64(&self.member(member).ty) {
            format!("pb_u2f({})", v)
        } else {
            format!("({} + 0.0)", v)
        }
    }

    /// The reader (`r`) while decoding, the writer (`w`) while encoding.
    fn coder(&self) -> &'static str {
        if self.mode == Mode::Encode { "w" } else { "r" }
    }
}

impl<D: LuaDialect> ExprLang for Scope<'_, D> {
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
        if ty == Ty::Float { self.float_of(place, member) } else { place }
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        let v = format!("pb_at({}, {})", self.place(member), index);
        if ty == Ty::Float { self.float_of(v, member) } else { v }
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let exact = D::EXACT_U64 && is_u64(&self.member(member).ty);
        let f = match (op, ty) {
            (AggOp::Sum, Ty::Float) if exact => "pb_sumuf",
            (AggOp::Product, Ty::Float) if exact => "pb_produf",
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

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "and" } else { "or" };
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
            Some((_, f)) => format!("pb_last{}", index(f)),
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

    fn version(&self) -> String {
        format!("{}:version_or({})", self.coder(), self.packet.version_bounds().1)
    }

    fn remaining(&self) -> String {
        "r:remaining_bytes()".into()
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let (hf, ht) = hole.unwrap_or(("0", "0"));
        format!("{}:checksum({}, {}, {}, {}, {})", self.coder(), algo.id(), from, to, hf, ht)
    }
}
