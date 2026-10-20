//! Expression evaluation with the semantics documented on [`TExpr`].

use std::collections::HashMap;

use super::value::Value;
use crate::ir::{AggOp, ArithOp, CmpOp, Func, LogicOp, Mark, TExpr, Ty, UnaryOp, ValueType};

/// An evaluated expression.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ev {
    I(i64),
    F(f64),
    B(bool),
}

impl Ev {
    pub fn int(self) -> i64 {
        match self {
            Ev::I(v) => v,
            Ev::F(v) => v as i64,
            Ev::B(b) => b as i64,
        }
    }

    fn float(self) -> f64 {
        match self {
            Ev::I(v) => v as f64,
            Ev::F(v) => v,
            Ev::B(b) => b as i64 as f64,
        }
    }

    pub fn bool(self) -> bool {
        match self {
            Ev::I(v) => v != 0,
            Ev::F(v) => v != 0.0,
            Ev::B(b) => b,
        }
    }
}

/// A checksum over recorded bit positions: (algorithm, from, to, hole from, hole to).
pub type ChecksumFn<'a> = &'a dyn Fn(u32, usize, usize, usize, usize) -> u64;

/// The current values of a packet's members (index-aligned with them), and
/// for derived fields the recorded positions and a way to compute checksums.
pub struct Env<'a> {
    pub values: &'a [Value],
    /// The packet's parameters (`TExpr::Param`).
    pub params: Vec<i64>,
    pub marks: Option<&'a HashMap<Mark, usize>>,
    pub checksum: Option<ChecksumFn<'a>>,
    /// In an `until` condition: the element just read.
    pub last: Option<&'a Value>,
    /// While decoding a calculated field: whole bytes left (`TExpr::Remaining`).
    pub remaining: Option<i64>,
}

impl<'a> Env<'a> {
    pub fn new(values: &'a [Value], params: &[i64]) -> Self {
        Env { values, params: params.to_vec(), marks: None, checksum: None, last: None, remaining: None }
    }

    fn mark(&self, m: Mark) -> usize {
        self.marks.and_then(|ms| ms.get(&m).copied()).unwrap_or(0)
    }
}

fn scalar(v: &Value, ty: Ty) -> Ev {
    match (v, ty) {
        (Value::Int(i), Ty::Float) => Ev::F(*i as i64 as f64),
        (Value::Int(i), _) => Ev::I(*i as i64),
        (Value::Float(f), Ty::Float) => Ev::F(*f),
        (Value::Float(f), _) => Ev::I(*f as i64),
        _ => {
            if ty == Ty::Float {
                Ev::F(0.0)
            } else {
                Ev::I(0)
            }
        }
    }
}

fn elements(v: &Value) -> Vec<Value> {
    match v {
        Value::List(items) => items.clone(),
        Value::Bytes(b) => b.iter().map(|x| Value::Int(*x as i128)).collect(),
        _ => Vec::new(),
    }
}

pub fn eval(e: &TExpr, env: &Env) -> Ev {
    match e {
        TExpr::IntLit(v) => Ev::I(*v),
        TExpr::FloatLit(v) => Ev::F(*v),
        TExpr::Remaining => Ev::I(env.remaining.unwrap_or(0)),
        TExpr::Ref { member, ty } => scalar(&env.values[*member], *ty),
        TExpr::Stored { member } => scalar(&env.values[*member], Ty::Int),
        TExpr::Index { member, index, ty } => {
            let i = eval(index, env).int();
            let items = elements(&env.values[*member]);
            match usize::try_from(i).ok().and_then(|i| items.get(i)) {
                Some(v) => scalar(v, *ty),
                None if *ty == Ty::Float => Ev::F(0.0),
                None => Ev::I(0),
            }
        }
        TExpr::Aggregate { member, op, ty } => {
            let items = elements(&env.values[*member]);
            if *ty == Ty::Float {
                let it = items.iter().map(|v| scalar(v, Ty::Float).float());
                Ev::F(match op {
                    AggOp::Sum => it.sum(),
                    AggOp::Product => it.product(),
                })
            } else {
                let it = items.iter().map(|v| scalar(v, Ty::Int).int());
                Ev::I(match op {
                    AggOp::Sum => it.fold(0i64, i64::wrapping_add),
                    AggOp::Product => it.fold(1i64, i64::wrapping_mul),
                })
            }
        }
        TExpr::Arith { op, a, b, ty } => {
            let (a, b) = (eval(a, env), eval(b, env));
            if *ty == Ty::Float {
                let (a, b) = (a.float(), b.float());
                Ev::F(match op {
                    ArithOp::Add => a + b,
                    ArithOp::Sub => a - b,
                    ArithOp::Mul => a * b,
                    ArithOp::Div => a / b,
                    ArithOp::Pow => a.powf(b),
                    _ => unreachable!("integer-only operator on floats"),
                })
            } else {
                Ev::I(op.apply(a.int(), b.int()))
            }
        }
        TExpr::Cmp { op, a, b } => {
            let (a, b) = (eval(a, env), eval(b, env));
            let ord = match (a, b) {
                (Ev::F(_), _) | (_, Ev::F(_)) => a.float().partial_cmp(&b.float()),
                _ => Some(a.int().cmp(&b.int())),
            };
            use std::cmp::Ordering::*;
            Ev::B(match (op, ord) {
                (CmpOp::Eq, o) => o == Some(Equal),
                (CmpOp::Ne, o) => o != Some(Equal),
                (CmpOp::Lt, o) => o == Some(Less),
                (CmpOp::Lte, o) => matches!(o, Some(Less | Equal)),
                (CmpOp::Gt, o) => o == Some(Greater),
                (CmpOp::Gte, o) => matches!(o, Some(Greater | Equal)),
            })
        }
        TExpr::Logic { op, a, b } => {
            let a = eval(a, env).bool();
            Ev::B(match op {
                LogicOp::And => a && eval(b, env).bool(),
                LogicOp::Or => a || eval(b, env).bool(),
            })
        }
        TExpr::Guard { cond, then, other, .. } => {
            if eval(cond, env).bool() {
                eval(then, env)
            } else {
                eval(other, env)
            }
        }
        TExpr::Call { func, args, ty } => {
            let args: Vec<Ev> = args.iter().map(|a| eval(a, env)).collect();
            match (func, ty) {
                (Func::Sqrt, _) => Ev::F(args[0].float().sqrt()),
                (Func::Min, Ty::Float) => Ev::F(args[0].float().min(args[1].float())),
                (Func::Max, Ty::Float) => Ev::F(args[0].float().max(args[1].float())),
                (Func::Min, _) => Ev::I(args[0].int().min(args[1].int())),
                (Func::Max, _) => Ev::I(args[0].int().max(args[1].int())),
            }
        }
        TExpr::Convert { e, to } => {
            let v = eval(e, env);
            match to {
                Ty::Int => Ev::I(v.int()),
                Ty::Float => Ev::F(v.float()),
                Ty::Bool => Ev::B(v.bool()),
            }
        }
        TExpr::Param { index } => Ev::I(env.params.get(*index).copied().unwrap_or(0)),
        TExpr::Last { field, ty } => {
            let v = match (env.last, field) {
                (Some(Value::Struct(s)), Some((_, name))) => s.get(name),
                (v, None) => v,
                _ => None,
            };
            v.map(|v| scalar(v, *ty)).unwrap_or(if *ty == Ty::Float { Ev::F(0.0) } else { Ev::I(0) })
        }
        TExpr::Len { member } => Ev::I(match &env.values[*member] {
            Value::List(items) => items.len(),
            Value::Bytes(b) => b.len(),
            Value::Str(s) => s.len(),
            _ => 0,
        } as i64),
        TExpr::Size { from, to } => Ev::I((env.mark(*to).saturating_sub(env.mark(*from)) / 8) as i64),
        TExpr::Checksum { algo, from, to, hole } => {
            let (hf, ht) = hole.map(|(a, b)| (env.mark(a), env.mark(b))).unwrap_or((0, 0));
            let sum = env.checksum.map(|f| f(algo.id(), env.mark(*from), env.mark(*to), hf, ht)).unwrap_or(0);
            Ev::I(sum as i64)
        }
        TExpr::Unary { op, e, ty } => {
            let v = eval(e, env);
            match (op, ty) {
                (UnaryOp::Neg, Ty::Float) => Ev::F(-v.float()),
                (UnaryOp::Neg, _) => Ev::I(v.int().wrapping_neg()),
                (UnaryOp::BitNot, _) => Ev::I(!v.int()),
                (UnaryOp::Not, _) => Ev::B(!v.bool()),
            }
        }
    }
}

/// Convert an evaluated expression to a member's type, wrapping integers to
/// the member's width like generated code does.
pub fn store(v: Ev, ty: &ValueType) -> Value {
    match ty {
        ValueType::Int { width, signed } => Value::Int(wrap(v.int(), *width, *signed)),
        ValueType::Float { width: 32 } => Value::Float(v.float() as f32 as f64),
        ValueType::Float { .. } => Value::Float(v.float()),
        _ => Value::Int(0),
    }
}

/// `v` truncated to `width` bits (two's complement), read back as signed or
/// unsigned.
pub fn wrap(v: i64, width: u32, signed: bool) -> i128 {
    if width >= 64 {
        return if signed { v as i128 } else { v as u64 as i128 };
    }
    let u = (v as u64) & ((1u64 << width) - 1);
    if signed { super::sext(u, width) as i128 } else { u as i128 }
}
