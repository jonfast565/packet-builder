//! Pieces shared by every backend: the expression walker and naming helpers.

use crate::ir::{AggOp, ArithOp, CmpOp, Func, LogicOp, Member, Packet, TExpr, Ty};

/// Options that affect generated code.
#[derive(Debug, Clone)]
pub struct GenOptions {
    /// Go package / C# namespace / C header guard stem.
    pub package: String,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions { package: "packets".to_string() }
    }
}

/// Whether an expression is evaluated while decoding (every member lives in
/// the target struct) or while encoding (calculated members are locals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Decode,
    Encode,
}

/// Language hooks used by [`emit_expr`]. Integer expressions have type i64,
/// float expressions f64 and boolean expressions the native bool.
pub trait ExprLang {
    fn int_lit(&self, v: i64) -> String;
    fn float_lit(&self, v: f64) -> String {
        format!("{:?}", v)
    }
    /// A scalar member converted to i64 (Ty::Int) or f64 (Ty::Float).
    fn member_ref(&self, member: usize, ty: Ty) -> String;
    /// Element `index` (an i64 expression) of an array member; 0 if out of range.
    fn index(&self, member: usize, index: String, ty: Ty) -> String;
    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String;
    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String;
    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        format!("({} {} {})", a, cmp_symbol(op), b)
    }
    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "&&" } else { "||" };
        format!("({} {} {})", a, sym, b)
    }
    fn guard(&self, cond: String, then: String, other: String, ty: Ty) -> String;
    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String;
    fn convert(&self, e: String, from: Ty, to: Ty) -> String;
}

pub fn cmp_symbol(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Gt => ">",
        CmpOp::Gte => ">=",
        CmpOp::Lt => "<",
        CmpOp::Lte => "<=",
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
    }
}

pub fn emit_expr<L: ExprLang + ?Sized>(l: &L, e: &TExpr) -> String {
    match e {
        TExpr::IntLit(v) => l.int_lit(*v),
        TExpr::FloatLit(v) => l.float_lit(*v),
        TExpr::Ref { member, ty } => l.member_ref(*member, *ty),
        TExpr::Index { member, index, ty } => l.index(*member, emit_expr(l, index), *ty),
        TExpr::Aggregate { member, op, ty } => l.aggregate(*member, *op, *ty),
        TExpr::Arith { op, a, b, ty } => l.arith(*op, emit_expr(l, a), emit_expr(l, b), *ty),
        TExpr::Cmp { op, a, b } => l.cmp(*op, emit_expr(l, a), emit_expr(l, b)),
        TExpr::Logic { op, a, b } => l.logic(*op, emit_expr(l, a), emit_expr(l, b)),
        TExpr::Guard { cond, then, other, ty } => {
            l.guard(emit_expr(l, cond), emit_expr(l, then), emit_expr(l, other), *ty)
        }
        TExpr::Call { func, args, ty } => {
            l.call(*func, args.iter().map(|a| emit_expr(l, a)).collect(), *ty)
        }
        TExpr::Convert { e, to } => l.convert(emit_expr(l, e), e.ty(), *to),
    }
}

/// Members referenced by expressions evaluated in `mode` (used by languages
/// that reject unused variables).
pub fn uses_member(packet: &Packet, m: usize) -> bool {
    let mut deps = Vec::new();
    for mem in &packet.members {
        if let Some(crate::ir::Count::Expr(e)) = &mem.array {
            e.deps(&mut deps);
        }
        if let crate::ir::MemberKind::Calculated(e) = &mem.kind {
            e.deps(&mut deps);
        }
    }
    deps.contains(&m)
}

pub fn is_calc(m: &Member) -> bool {
    matches!(m.kind, crate::ir::MemberKind::Calculated(_))
}

/// `snake_case` / `camelCase` / `kebab` → `PascalCase`.
pub fn pascal_case(name: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for c in name.chars() {
        if c == '_' || c == '-' {
            upper = true;
            continue;
        }
        if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, 'F');
    }
    out
}

/// `PascalCase` / `camelCase` → `snake_case`.
pub fn snake_case(name: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let prev_lower = i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
            let next_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();
            if i > 0 && chars[i - 1] != '_' && (prev_lower || (next_lower && chars[i - 1].is_uppercase())) {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(*c);
        }
    }
    out
}

pub fn indent(code: &str, levels: usize, unit: &str) -> String {
    let pad = unit.repeat(levels);
    code.lines()
        .map(|l| if l.trim().is_empty() { "\n".to_string() } else { format!("{}{}\n", pad, l) })
        .collect()
}

pub fn mask(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
}

/// Line-oriented output buffer with indentation.
pub struct Out {
    pub buf: String,
    level: usize,
    unit: &'static str,
}

impl Out {
    pub fn new(unit: &'static str) -> Self {
        Out { buf: String::new(), level: 0, unit }
    }

    pub fn line(&mut self, s: impl AsRef<str>) {
        let s = s.as_ref();
        if s.is_empty() {
            self.buf.push('\n');
            return;
        }
        for l in s.lines() {
            self.buf.push_str(&self.unit.repeat(self.level));
            self.buf.push_str(l);
            self.buf.push('\n');
        }
    }

    /// Emit `s` and indent the following lines.
    pub fn open(&mut self, s: impl AsRef<str>) {
        self.line(s);
        self.level += 1;
    }

    /// Dedent, then emit `s`.
    pub fn close(&mut self, s: impl AsRef<str>) {
        self.level = self.level.saturating_sub(1);
        self.line(s);
    }

    pub fn push(&mut self) {
        self.level += 1;
    }

    pub fn pop(&mut self) {
        self.level = self.level.saturating_sub(1);
    }
}
