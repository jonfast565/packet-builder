//! Type-checking of source expressions into [`TExpr`].

use super::context::Ctx;
use super::types::field_value_type;
use crate::errors::Diagnostic;
use crate::ir::expr::{AggOp, ArithOp, CmpOp, Func, LogicOp, TExpr, Ty, coerce, numeric_join};
use crate::ir::model::ValueType;
use crate::models::parsing_models::{ExprNode, PacketItem, Span};

impl<'a> Ctx<'a> {
    pub fn check_expr(&mut self, e: &ExprNode, span: Span) -> Option<TExpr> {
        match self.typecheck(e) {
            Ok(t) => Some(t),
            Err(msg) => {
                self.diags.push(Diagnostic::new(msg, span));
                None
            }
        }
    }

    fn lookup(&self, name: &str) -> Result<usize, String> {
        self.names
            .get(name)
            .copied()
            .ok_or_else(|| format!("unknown field `{}` in packet `{}`", name, self.packet.name))
    }

    fn scalar_ty(&self, vt: &ValueType, name: &str) -> Result<Ty, String> {
        match vt {
            ValueType::Int { .. } => Ok(Ty::Int),
            ValueType::Float { .. } => Ok(Ty::Float),
            ValueType::Mac => Err(format!("`{}` is a mac address and cannot be used in an expression", name)),
            ValueType::Packet(_) => Err(format!("`{}` is a nested packet and cannot be used in an expression", name)),
            ValueType::Str => Err(format!("`{}` is a string and cannot be used in an expression", name)),
        }
    }

    fn typecheck(&self, e: &ExprNode) -> Result<TExpr, String> {
        use ExprNode::*;
        Ok(match e {
            NoExpr => return Err("empty expression".into()),
            UnsignedInteger64Value(v) => TExpr::IntLit(*v as i64),
            Integer64Value(v) => TExpr::IntLit(*v),
            Float64Value(v) => TExpr::FloatLit(*v),
            StringValue(_) => return Err("string literals are not supported in expressions".into()),
            ParenthesizedExpr(x) => self.typecheck(x)?,
            ValueReference(name, index) => {
                let idx = self.lookup(name)?;
                let m = &self.members[idx];
                let ty = self.scalar_ty(&m.ty, name)?;
                let is_array = self.is_array(idx);
                match index {
                    None => {
                        if is_array {
                            return Err(format!(
                                "`{}` is an array; index it (`{}[i]`) or use `sumof {}`",
                                name, name, name
                            ));
                        }
                        TExpr::Ref { member: idx, ty }
                    }
                    Some(ix) => {
                        if !is_array {
                            return Err(format!("`{}` is not an array and cannot be indexed", name));
                        }
                        let ix = coerce(self.typecheck(ix)?, Ty::Int);
                        TExpr::Index { member: idx, index: Box::new(ix), ty }
                    }
                }
            }
            AggregateSum(name) | AggregateProduct(name) => {
                let idx = self.lookup(name)?;
                if !self.is_array(idx) {
                    return Err(format!("`{}` is not an array", name));
                }
                let ty = self.scalar_ty(&self.members[idx].ty, name)?;
                let op = if matches!(e, AggregateSum(_)) { AggOp::Sum } else { AggOp::Product };
                TExpr::Aggregate { member: idx, op, ty }
            }
            ActivationRecord(fname, args) => {
                let args = args.iter().map(|a| self.typecheck(a)).collect::<Result<Vec<_>, _>>()?;
                match fname.as_str() {
                    "sqrt" => {
                        if args.len() != 1 {
                            return Err("sqrt takes exactly one argument".into());
                        }
                        let a = coerce(args.into_iter().next().unwrap(), Ty::Float);
                        TExpr::Call { func: Func::Sqrt, args: vec![a], ty: Ty::Float }
                    }
                    "min" | "max" => {
                        if args.len() != 2 {
                            return Err(format!("{} takes exactly two arguments", fname));
                        }
                        let mut it = args.into_iter();
                        let (a, b) = (it.next().unwrap(), it.next().unwrap());
                        let ty = numeric_join(a.ty(), b.ty());
                        let func = if fname == "min" { Func::Min } else { Func::Max };
                        TExpr::Call { func, args: vec![coerce(a, ty), coerce(b, ty)], ty }
                    }
                    other => return Err(format!("unknown function `{}`", other)),
                }
            }
            GuardExpression(c, t, o) => {
                let cond = coerce(self.typecheck(c)?, Ty::Bool);
                let (t, o) = (self.typecheck(t)?, self.typecheck(o)?);
                let ty = if t.ty() == Ty::Bool && o.ty() == Ty::Bool { Ty::Bool } else { numeric_join(t.ty(), o.ty()) };
                TExpr::Guard { cond: Box::new(cond), then: Box::new(coerce(t, ty)), other: Box::new(coerce(o, ty)), ty }
            }
            Plus(a, b) | Minus(a, b) | Mult(a, b) | Div(a, b) | Pow(a, b) => {
                let (a, b) = (self.typecheck(a)?, self.typecheck(b)?);
                let ty = numeric_join(a.ty(), b.ty());
                let op = match e {
                    Plus(..) => ArithOp::Add,
                    Minus(..) => ArithOp::Sub,
                    Mult(..) => ArithOp::Mul,
                    Div(..) => ArithOp::Div,
                    _ => ArithOp::Pow,
                };
                TExpr::Arith { op, a: Box::new(coerce(a, ty)), b: Box::new(coerce(b, ty)), ty }
            }
            Gt(a, b) | Gte(a, b) | Lt(a, b) | Lte(a, b) | Equals(a, b) | NotEquals(a, b) => {
                let (a, b) = (self.typecheck(a)?, self.typecheck(b)?);
                let ty = numeric_join(a.ty(), b.ty());
                let op = match e {
                    Gt(..) => CmpOp::Gt,
                    Gte(..) => CmpOp::Gte,
                    Lt(..) => CmpOp::Lt,
                    Lte(..) => CmpOp::Lte,
                    Equals(..) => CmpOp::Eq,
                    _ => CmpOp::Ne,
                };
                TExpr::Cmp { op, a: Box::new(coerce(a, ty)), b: Box::new(coerce(b, ty)) }
            }
            And(a, b) | Or(a, b) => {
                let a = coerce(self.typecheck(a)?, Ty::Bool);
                let b = coerce(self.typecheck(b)?, Ty::Bool);
                let op = if matches!(e, And(..)) { LogicOp::And } else { LogicOp::Or };
                TExpr::Logic { op, a: Box::new(a), b: Box::new(b) }
            }
        })
    }

    /// Arrays are known after pass 2; before that, look at the source.
    pub fn is_array(&self, idx: usize) -> bool {
        if self.members[idx].array.is_some() {
            return true;
        }
        let name = &self.members[idx].name;
        self.packet.items.iter().any(
            |it| matches!(it, PacketItem::Field(f) if &f.id == name && f.array.is_some() && field_value_type(f) != ValueType::Str),
        )
    }
}
