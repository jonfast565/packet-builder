//! COBOL expressions. COBOL has no expression syntax for most of what the
//! language needs (wrapping 64-bit arithmetic, shifts, bit operations,
//! conditional values), so each node becomes statements that leave its
//! value in a temporary: integers and booleans (0 or 1) in BINARY-DOUBLE,
//! floats in FLOAT-LONG. [`Ev`] collects the statements while
//! `common::emit_expr` walks the tree, and [`Ev::eval`] writes them out and
//! returns the operand holding the result.
//!
//! This is why `ExprLang` is implemented for `Ev` (a `Scope` plus the
//! statement buffer) rather than for `Scope` itself.

use std::cell::RefCell;

use super::locals::Locals;
use super::naming::{Cobol, calc_local, call, cob_literal, elem_kind, mark_local, member_offset, param_local};
use crate::generators::common::union::held_arm;
use crate::generators::common::{ExprLang, Mode, Out, Scope, emit_expr};
use crate::ir::{
    AggOp, ArithOp, Arm, Checksum, CmpOp, Func, LogicOp, Module, Packet, PacketRef, TExpr, Ty, UnaryOp, ValueType,
};

pub struct Ev<'a> {
    pub scope: Scope<'a, Cobol>,
    pub module: &'a Module,
    pub locals: &'a Locals,
    buf: RefCell<Vec<String>>,
}

impl<'a> Ev<'a> {
    pub fn new(module: &'a Module, packet: &'a Packet, mode: Mode, locals: &'a Locals) -> Self {
        Ev { scope: Scope::new(packet, mode), module, locals, buf: RefCell::new(Vec::new()) }
    }

    /// Write the statements that compute `e`; returns the operand holding it.
    pub fn eval(&self, out: &mut Out, e: &TExpr) -> String {
        let v = emit_expr(self, e);
        for s in self.buf.borrow_mut().drain(..) {
            out.line(s);
        }
        v
    }

    fn emit(&self, s: impl Into<String>) {
        self.buf.borrow_mut().push(s.into());
    }

    /// Where an expression reads member `member`: its field, or while
    /// encoding the local holding a calculated or derived member.
    pub fn place(&self, member: usize) -> String {
        if self.scope.place(member).starts_with("pbc_") { calc_local(member) } else { self.field(member) }
    }

    pub fn field(&self, member: usize) -> String {
        self.scope.field(self.scope.member(member))
    }

    fn temp(&self, ty: Ty) -> String {
        if ty == Ty::Float { self.locals.float() } else { self.locals.int() }
    }

    /// `t := 1 if <cond> else 0`.
    fn flag(&self, cond: String) -> String {
        let t = self.locals.int();
        self.emit(format!("IF {}\n    MOVE 1 TO {}\nELSE\n    MOVE 0 TO {}\nEND-IF", cond, t, t));
        t
    }

    fn iop(&self, op: u32, a: &str, b: &str) -> String {
        let t = self.locals.int();
        self.emit(format!(
            "MOVE {} TO PB-X\nMOVE {} TO PB-Y\nMOVE {} TO PB-OP\nCALL \"PB-IOP\"\nMOVE PB-Z TO {}",
            a, b, op, t
        ));
        t
    }

    fn fop(&self, op: u32, a: &str, b: &str) -> String {
        let t = self.locals.float();
        self.emit(format!(
            "MOVE {} TO PB-FX\nMOVE {} TO PB-FY\nMOVE {} TO PB-OP\nCALL \"PB-FOP\"\nMOVE PB-FZ TO {}",
            a, b, op, t
        ));
        t
    }

    fn array_call(&self, member: usize, routine: &str, setup: &str, ty: Ty) -> String {
        let m = self.scope.member(member);
        let f = self.field(member);
        let kind = if m.ty == ValueType::Str { 1 } else { elem_kind(&m.ty) };
        let t = self.temp(ty);
        let result = if ty == Ty::Float { "PB-FZ" } else { "PB-Z" };
        self.emit(format!(
            "SET PB-GP TO {f}-P\nMOVE {f}-N TO PB-A1\nMOVE {kind} TO PB-A2\n{setup}CALL \"{routine}\"\nMOVE {result} TO {t}"
        ));
        t
    }
}

impl ExprLang for Ev<'_> {
    fn int_lit(&self, v: i64) -> String {
        v.to_string()
    }

    fn float_lit(&self, v: f64) -> String {
        let t = self.locals.float();
        self.emit(format!("MOVE {} TO PB-FX-B\nMOVE PB-FX TO {}", v.to_bits() as i64, t));
        t
    }

    fn member_ref(&self, member: usize, _ty: Ty) -> String {
        self.place(member)
    }

    fn index(&self, member: usize, index: String, ty: Ty) -> String {
        self.array_call(member, "PB-INDEX", &format!("MOVE {} TO PB-X\n", index), ty)
    }

    fn aggregate(&self, member: usize, op: AggOp, ty: Ty) -> String {
        let code = if op == AggOp::Sum { 1 } else { 2 };
        self.array_call(member, "PB-AGG", &format!("MOVE {} TO PB-A3\n", code), ty)
    }

    fn arith(&self, op: ArithOp, a: String, b: String, ty: Ty) -> String {
        if ty == Ty::Float {
            let code = match op {
                ArithOp::Add => 1,
                ArithOp::Sub => 2,
                ArithOp::Mul => 3,
                ArithOp::Div => 4,
                _ => 6,
            };
            return self.fop(code, &a, &b);
        }
        let code = match op {
            ArithOp::Add => 1,
            ArithOp::Sub => 2,
            ArithOp::Mul => 3,
            ArithOp::Div => 4,
            ArithOp::Mod => 5,
            ArithOp::Pow => 6,
            ArithOp::Shl => 7,
            ArithOp::Shr => 8,
            ArithOp::BitAnd => 9,
            ArithOp::BitOr => 10,
            ArithOp::BitXor => 11,
        };
        self.iop(code, &a, &b)
    }

    fn unary(&self, op: UnaryOp, e: String, ty: Ty) -> String {
        match (op, ty) {
            (UnaryOp::Not, _) => self.flag(format!("{} = 0", e)),
            (UnaryOp::Neg, Ty::Float) => self.fop(12, &e, "0"),
            (UnaryOp::Neg, _) => self.iop(12, &e, "0"),
            (UnaryOp::BitNot, _) => self.iop(13, &e, "0"),
        }
    }

    fn cmp(&self, op: CmpOp, a: String, b: String) -> String {
        let sym = match op {
            CmpOp::Gt => ">",
            CmpOp::Gte => ">=",
            CmpOp::Lt => "<",
            CmpOp::Lte => "<=",
            CmpOp::Eq => "=",
            CmpOp::Ne => "NOT =",
        };
        self.flag(format!("{} {} {}", a, sym, b))
    }

    fn logic(&self, op: LogicOp, a: String, b: String) -> String {
        let sym = if op == LogicOp::And { "AND" } else { "OR" };
        self.flag(format!("{} NOT = 0 {} {} NOT = 0", a, sym, b))
    }

    fn guard(&self, cond: String, then: String, other: String, ty: Ty) -> String {
        let t = self.temp(ty);
        self.emit(format!(
            "IF {} NOT = 0\n    MOVE {} TO {}\nELSE\n    MOVE {} TO {}\nEND-IF",
            cond, then, t, other, t
        ));
        t
    }

    fn call(&self, func: Func, args: Vec<String>, ty: Ty) -> String {
        match (func, ty) {
            (Func::Sqrt, _) => self.fop(22, &args[0], "0"),
            (Func::Min, Ty::Float) => self.fop(20, &args[0], &args[1]),
            (Func::Max, Ty::Float) => self.fop(21, &args[0], &args[1]),
            (f, _) => {
                let t = self.locals.int();
                let sym = if f == Func::Min { "<" } else { ">" };
                self.emit(format!(
                    "IF {a} {sym} {b}\n    MOVE {a} TO {t}\nELSE\n    MOVE {b} TO {t}\nEND-IF",
                    a = args[0],
                    b = args[1]
                ));
                t
            }
        }
    }

    fn convert(&self, e: String, from: Ty, to: Ty) -> String {
        match (from, to) {
            (Ty::Bool | Ty::Int, Ty::Float) => {
                let t = self.locals.float();
                self.emit(format!("MOVE {} TO {}", e, t));
                t
            }
            (Ty::Float, Ty::Int) => {
                let t = self.locals.int();
                self.emit(format!("MOVE {} TO PB-FX\nCALL \"PB-FTOI\"\nMOVE PB-Z TO {}", e, t));
                t
            }
            (Ty::Int | Ty::Float, Ty::Bool) => self.flag(format!("{} NOT = 0", e)),
            _ => e,
        }
    }

    fn last(&self, field: Option<(&str, &str)>, ty: Ty) -> String {
        let Some((packet, f)) = field else {
            return if ty == Ty::Float { "PL-LASTF".into() } else { "PL-LASTI".into() };
        };
        let p = self.module.packets.iter().find(|p| p.name == packet).expect("element packet exists");
        let i = p.members.iter().position(|m| m.name == f).expect("element field exists");
        let ptr = self.locals.var("PL-LPTR", "USAGE POINTER");
        let (group, val) = match p.members[i].ty {
            ValueType::Float { width: 32 } => ("LK-F4G", "LK-F4"),
            ValueType::Float { .. } => ("LK-F8G", "LK-F8"),
            _ => ("LK-I8G", "LK-I8"),
        };
        let t = self.temp(ty);
        self.emit(format!(
            "SET {ptr} TO PL-LASTP\nSET {ptr} UP BY {off}\nSET ADDRESS OF {group} TO {ptr}\nMOVE {val} TO {t}",
            off = member_offset(self.module, p, i)
        ));
        t
    }

    fn param(&self, index: usize) -> String {
        param_local(index)
    }

    fn len(&self, member: usize) -> String {
        format!("{}-N", self.field(member))
    }

    fn remaining(&self) -> String {
        let t = self.locals.int();
        self.emit(format!("COMPUTE {} = (PB-LIMIT - PB-POS) / 8", t));
        t
    }

    fn version(&self) -> String {
        let latest = self.scope.packet.version_bounds().1;
        let t = self.locals.int();
        self.emit(format!("IF PB-VER = 0\n    MOVE {} TO {}\nELSE\n    MOVE PB-VER TO {}\nEND-IF", latest, t, t));
        t
    }

    fn stored(&self, member: usize) -> String {
        self.field(member)
    }

    fn holds(&self, member: usize, arm: &str) -> String {
        let (k, _) = held_arm(self.scope.packet, member, arm);
        self.flag(format!("{}-K = {}", self.field(member), k))
    }

    fn size(&self, from: &str, to: &str) -> String {
        let t = self.locals.int();
        self.emit(format!("COMPUTE {} = ({} - {}) / 8", t, mark_local(to), mark_local(from)));
        t
    }

    fn checksum(&self, algo: Checksum, from: &str, to: &str, hole: Option<(&str, &str)>) -> String {
        let (hf, ht) = match hole {
            Some((a, b)) => (mark_local(a), mark_local(b)),
            None => ("0".into(), "0".into()),
        };
        let writer = u32::from(self.scope.mode == Mode::Encode);
        let t = self.locals.int();
        self.emit(format!(
            "MOVE {} TO PB-A1\nMOVE {} TO PB-X\nMOVE {} TO PB-Y\nMOVE {} TO PB-A4\nMOVE {} TO PB-A5\nMOVE {} TO PB-A6\nCALL \"PB-CKSUM\"\nMOVE PB-Z TO {}",
            algo.id(),
            mark_local(from),
            mark_local(to),
            hf,
            ht,
            writer,
            t
        ));
        t
    }
}

/// Store the i64 or f64 operand `v` into `dest`, a value of type `ty`:
/// integers are cut to their width (sign-extended when signed).
pub fn store_value(out: &mut Out, v: &str, ty: &ValueType, dest: &str) {
    match ty {
        ValueType::Int { width, signed } if *width < 64 => {
            out.line(format!("MOVE {} TO PB-X", v));
            out.line(format!("MOVE {} TO PB-A1", width));
            out.line(format!("MOVE {} TO PB-A2", u32::from(*signed)));
            out.line("CALL \"PB-TRUNC\"");
            out.line(format!("MOVE PB-Z TO {}", dest));
        }
        _ => out.line(format!("MOVE {} TO {}", v, dest)),
    }
}

/// After a runtime or packet program that can fail: stop when it did.
pub const RC: &str = "IF PB-RC NOT = 0 GOBACK END-IF";

/// `CALL "<prog>"`, then stop if it failed.
pub fn call_rt(out: &mut Out, prog: &str) {
    out.line(format!("CALL \"{}\"", prog));
    out.line(RC);
}

/// Fail with error `kind` (see the runtime) and `message`, and return.
pub fn fail(out: &mut Out, kind: u32, message: &str) {
    out.line(format!("MOVE {} TO PB-MSG", cob_literal(message)));
    out.line(format!("MOVE {} TO PB-A1", kind));
    out.line("MOVE 0 TO PB-A2");
    out.line("CALL \"PB-FAIL\"");
    out.line("GOBACK");
}

/// ` PL-T1 PL-T2`: the arguments for nested packet `r`, each evaluated into
/// a temporary of its parameter's type.
pub fn call_args(ev: &Ev, out: &mut Out, r: &PacketRef) -> String {
    let mut s = String::new();
    for (e, ty) in r.typed_args() {
        let v = ev.eval(out, e);
        let t = if matches!(ty, ValueType::Float { .. }) { ev.locals.float() } else { ev.locals.int() };
        store_value(out, &v, ty, &t);
        s.push(' ');
        s.push_str(&t);
    }
    s
}

/// Call a program of nested packet `name` (`what`: DEC, ENC, ...) on
/// `target` with `args`, then point P-REC back at this invocation's record
/// (recursive programs share their LINKAGE addresses) and stop on errors.
pub fn call_packet(out: &mut Out, module: &Module, name: &str, what: &str, target: &str, args: &str) {
    out.line(format!("CALL {} USING {}{}", call(module, name, what), target, args));
    out.line("SET ADDRESS OF P-REC TO PL-SELF");
    if what == "DEC" || what == "ENC" {
        out.line(RC);
    }
}

/// The condition under which the selector in `var` picks `arm`, or None
/// when every value does.
pub fn arm_test(arm: &Arm, arms: &[Arm], var: &str) -> Option<String> {
    let any = |vals: &[i64]| vals.iter().map(|v| format!("{} = {}", var, v)).collect::<Vec<_>>().join(" OR ");
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("NOT ({})", any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}
