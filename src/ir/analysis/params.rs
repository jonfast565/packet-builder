//! Packet parameters (`packet Body(version uint8)`), the arguments nested
//! packets take (`b Body(version)`), and packets stored elsewhere
//! (`name Foo at offset`).

use std::collections::HashMap;

use super::context::Ctx;
use super::packet::PacketBuilder;
use super::types::{field_value_type, value_type};
use crate::ast::{ExprNode, PacketExprList, PacketItem, Span, TypeExpr, TypeNode};
use crate::errors::Diagnostic;
use crate::ir::expr::{TExpr, Ty, coerce};
use crate::ir::model::{PacketRef, Param, Step, ValueType};

/// What other packets may know about a packet before it is analyzed (it may
/// not be, when packets refer to each other): its parameters and the types
/// of its single-valued members (for `until last.kind == ...`).
#[derive(Default)]
pub(super) struct Sig {
    pub params: Vec<Param>,
    pub fields: HashMap<String, ValueType>,
}

pub(super) type Sigs = HashMap<String, Sig>;

/// The signature of every packet.
pub(super) fn signatures(list: &PacketExprList, diags: &mut Vec<Diagnostic>) -> Sigs {
    let mut sigs = Sigs::new();
    for p in &list.packets {
        let mut sig = Sig::default();
        for param in &p.params {
            let ty = match &param.ty {
                t @ (TypeNode::Bits { .. } | TypeNode::Varint(_)) => value_type(t),
                t if t.integer_info().is_some() && !matches!(t, TypeNode::Bytes | TypeNode::Char) => value_type(t),
                _ => {
                    diags.push(Diagnostic::new(
                        format!("parameter `{}` of `{}` must have an integer type", param.name, p.name),
                        param.span,
                    ));
                    ValueType::Int { width: 64, signed: true }
                }
            };
            if sig.params.iter().any(|x| x.name == param.name) {
                diags.push(Diagnostic::new(
                    format!("`{}` is declared more than once in packet `{}`", param.name, p.name),
                    param.span,
                ));
            }
            sig.params.push(Param { name: param.name.clone(), ty });
        }
        for item in &p.items {
            match item {
                PacketItem::Field(f) if f.id != "_" && f.array.is_none() && f.until.is_none() => {
                    sig.fields.insert(f.id.clone(), field_value_type(f));
                }
                PacketItem::Bitfield(b) => {
                    for m in b.members.iter().filter(|m| m.name != "_") {
                        sig.fields.insert(m.name.clone(), ValueType::Int { width: m.width, signed: m.signed });
                    }
                }
                PacketItem::Calculated(c) if c.data_type.integer_info().is_some() => {
                    sig.fields.insert(c.name.clone(), value_type(&c.data_type));
                }
                _ => {}
            }
        }
        sigs.insert(p.name.clone(), sig);
    }
    sigs
}

impl<'a> Ctx<'a> {
    /// The packet's parameter `name`, as an expression.
    pub fn param(&self, name: &str) -> Option<TExpr> {
        self.params.iter().position(|p| p.name == name).map(|index| TExpr::Param { index })
    }

    /// Parameters may not share a name with a member.
    pub fn check_param_names(&mut self) {
        for p in self.params.clone() {
            if self.names.contains_key(&p.name) {
                self.diags.push(Diagnostic::new(
                    format!("`{}` is both a parameter and a field of packet `{}`", p.name, self.packet.name),
                    self.packet.span,
                ));
            }
        }
    }
}

impl PacketBuilder<'_> {
    /// `Name(args)`: type-check the arguments against `Name`'s parameters.
    /// They may only use values known at that point.
    pub(super) fn packet_ref(&mut self, name: &str, args: &[ExprNode], span: Span, field: &str) -> PacketRef {
        let types: Vec<ValueType> =
            self.ctx.sigs.get(name).map(|s| s.params.iter().map(|p| p.ty.clone()).collect()).unwrap_or_default();
        let want = types.len();
        if args.len() != want {
            self.ctx.diags.push(Diagnostic::new(
                format!("packet `{}` takes {} argument(s), but `{}` passes {}", name, want, field, args.len()),
                span,
            ));
        }
        let mut out = Vec::new();
        for a in args {
            let e = self.ctx.check_expr(a, span).map(|t| coerce(t, Ty::Int)).unwrap_or(TExpr::IntLit(0));
            if e.ty() != Ty::Int {
                self.ctx.diags.push(Diagnostic::new(format!("the arguments of `{}` must be integers", field), span));
            }
            self.ctx.require_available(&e, &self.available, &self.scheduled, span, "arguments", field);
            out.push(e);
        }
        PacketRef { name: name.to_string(), args: out, types }
    }

    /// `name Foo at [root] offset`: a single packet read from elsewhere. It
    /// takes no room where it is declared.
    pub(super) fn lay_out_at(&mut self, f: &TypeExpr) {
        let at = f.at.as_ref().expect("at field");
        let TypeNode::Packet(name) = &f.expr else {
            self.ctx
                .diags
                .push(Diagnostic::new(format!("`{}` uses `at`, so it must be a single packet", f.id), f.span));
            return;
        };
        if f.array.is_some() || f.until.is_some() || f.window.is_some() || f.derive.is_some() || f.align.is_some() {
            self.ctx.diags.push(Diagnostic::new(
                format!("`{}` uses `at`, so it cannot also have a length, `until`, `size`, `align` or `=`", f.id),
                f.span,
            ));
        }
        let Some(&member) = self.ctx.names.get(&f.id) else { return };
        let offset = self.ctx.check_expr(&at.offset, f.span).map(|t| coerce(t, Ty::Int)).unwrap_or(TExpr::IntLit(0));
        self.ctx.require_available(&offset, &self.available, &self.scheduled, f.span, "offset", &f.id);
        let target = self.packet_ref(name, &f.args, f.span, &f.id);
        self.steps.push(Step::At { member, target, offset, root: at.root });
        self.available.insert(member);
    }
}

/// Packets in an order where nested packets come first. A packet may contain
/// itself only through an array (`[n]`, `[]`, `until`) or an `at` field,
/// which every language stores out of line; such references may point to a
/// packet analyzed later.
pub(super) fn packet_order(
    list: &PacketExprList,
    by_name: &HashMap<String, usize>,
) -> Result<Vec<usize>, Vec<Diagnostic>> {
    struct Walk<'a> {
        list: &'a PacketExprList,
        by_name: &'a HashMap<String, usize>,
        state: Vec<u8>, // 0 = new, 1 = visiting, 2 = done
        /// Packets being visited, and whether the reference to the next one
        /// is stored out of line.
        stack: Vec<(usize, bool)>,
        order: Vec<usize>,
        diags: Vec<Diagnostic>,
    }

    /// References from item `item`: (packet name, out of line, span).
    fn refs(item: &PacketItem) -> Vec<(&String, bool, Span)> {
        match item {
            PacketItem::Field(f) => match &f.expr {
                TypeNode::Packet(name) => {
                    let out_of_line = f.array.is_some() || f.until.is_some() || f.at.is_some();
                    vec![(name, out_of_line, f.span)]
                }
                _ => Vec::new(),
            },
            PacketItem::Switch(sw) => sw
                .arms
                .iter()
                .filter_map(|a| match &a.ty {
                    Some((TypeNode::Packet(name), ..)) => Some((name, false, a.span)),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    impl Walk<'_> {
        fn visit(&mut self, i: usize) {
            if self.state[i] != 0 {
                return;
            }
            self.state[i] = 1;
            for item in &self.list.packets[i].items {
                for (name, out_of_line, span) in refs(item) {
                    let Some(&j) = self.by_name.get(name) else {
                        self.diags.push(Diagnostic::new(format!("unknown type `{}`", name), span).with_note(
                            "built-in types are uint8..uint64, int8..int64, uN/iN, float32, float64, macaddress, datetime, bytes",
                        ));
                        continue;
                    };
                    if self.state[j] == 1 {
                        // A cycle: fine if one of its references is out of line.
                        let from = self.stack.iter().position(|(k, _)| *k == j).unwrap_or(self.stack.len());
                        if !out_of_line && !self.stack[from..].iter().any(|(_, o)| *o) {
                            self.diags.push(
                                Diagnostic::new(format!("packet `{}` contains itself", name), span)
                                    .with_note("a packet may only contain itself through an array or an `at` field"),
                            );
                        }
                        continue;
                    }
                    self.stack.push((i, out_of_line));
                    self.visit(j);
                    self.stack.pop();
                }
            }
            self.state[i] = 2;
            self.order.push(i);
        }
    }

    let mut walk = Walk {
        list,
        by_name,
        state: vec![0; list.packets.len()],
        stack: Vec::new(),
        order: Vec::new(),
        diags: Vec::new(),
    };
    for i in 0..list.packets.len() {
        walk.visit(i);
    }
    if walk.diags.is_empty() { Ok(walk.order) } else { Err(walk.diags) }
}
