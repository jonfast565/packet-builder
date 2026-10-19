//! Analysis of one packet, as a builder that runs its passes in order:
//!
//! 1. declare every member, so expressions can refer to any of them;
//! 2. resolve array counts (they need the full name table);
//! 3. type-check calculated fields;
//! 4. lay out the wire steps, tracking alignment and decode order;
//! 5. final checks and the encode-time calculated fields.

use std::collections::{HashMap, HashSet};

use super::context::Ctx;
use super::cursor::{Cursor, const_factor};
use super::types::{field_value_type, natural_align, value_type};
use crate::ast::{ArrayLength, BitOrder, BitfieldExpr, Endianness, PacketExpr, PacketItem, TypeExpr, TypeNode};
use crate::errors::Diagnostic;
use crate::ir::expr::{TExpr, Ty, coerce};
use crate::ir::model::{BitPart, Codec, Count, MemberKind, Packet, Step, StrMode, ValueType};

pub(super) struct PacketBuilder<'a> {
    p: &'a PacketExpr,
    ctx: Ctx<'a>,
    default_endian: Endianness,
    /// Count of every `Field` item, in item order (pass 2).
    field_counts: Vec<Option<Count>>,
    steps: Vec<Step>,
    /// Members decoded so far.
    available: HashSet<usize>,
    /// Calculated members already given a `Calc` step.
    scheduled: HashSet<usize>,
    cursor: Cursor,
    open_ended: bool,
    /// Alignment of this packet when nested (C struct rules under `align N`).
    alignment: u64,
}

impl<'a> PacketBuilder<'a> {
    pub fn new(p: &'a PacketExpr, done: &'a HashMap<String, Packet>) -> Self {
        PacketBuilder {
            p,
            ctx: Ctx::new(p, done),
            default_endian: p.endianness.clone().unwrap_or(Endianness::Le),
            field_counts: Vec::new(),
            steps: Vec::new(),
            available: HashSet::new(),
            scheduled: HashSet::new(),
            cursor: Cursor::START,
            open_ended: false,
            alignment: 1,
        }
    }

    pub fn build(mut self) -> Result<Packet, Vec<Diagnostic>> {
        self.declare_members();
        self.resolve_counts();
        self.resolve_calcs();
        self.lay_out();
        self.finish()
    }

    /// Pass 1: declare every member so expressions can refer to any of them.
    fn declare_members(&mut self) {
        let ctx = &mut self.ctx;
        for item in &self.p.items {
            match item {
                PacketItem::Field(f) => {
                    if f.id == "_" {
                        continue;
                    }
                    ctx.declare(&f.id, field_value_type(f), MemberKind::Stored, f.span);
                }
                PacketItem::Bitfield(b) => {
                    for m in &b.members {
                        if m.name == "_" {
                            continue;
                        }
                        ctx.declare(
                            &m.name,
                            ValueType::Int { width: m.width, signed: m.signed },
                            MemberKind::BitfieldPart,
                            m.span,
                        );
                    }
                }
                PacketItem::Calculated(c) => {
                    let ty = match &c.data_type {
                        TypeNode::MacAddress
                        | TypeNode::Bytes
                        | TypeNode::Packet(_)
                        | TypeNode::Str
                        | TypeNode::CStr
                        | TypeNode::PrefixedStr { .. } => {
                            ctx.diags.push(Diagnostic::new(
                                format!("calculated field `{}` must have a numeric type", c.name),
                                c.span,
                            ));
                            ValueType::Int { width: 64, signed: true }
                        }
                        t => value_type(t),
                    };
                    ctx.declare(&c.name, ty, MemberKind::Calculated(TExpr::IntLit(0)), c.span);
                }
                PacketItem::Align(..) => {}
            }
        }
    }

    /// Pass 2: array counts (need the full name table).
    fn resolve_counts(&mut self) {
        let ctx = &mut self.ctx;
        for item in &self.p.items {
            if let PacketItem::Field(f) = item {
                let count = match &f.array {
                    None => None,
                    Some(ArrayLength::Remaining) => Some(Count::Remaining),
                    Some(ArrayLength::Expr(e)) => ctx.check_expr(e, f.span).map(|t| Count::Expr(coerce(t, Ty::Int))),
                };
                if let Some(&idx) = ctx.names.get(&f.id)
                    && f.id != "_"
                    && field_value_type(f) != ValueType::Str
                {
                    ctx.members[idx].array = count.clone();
                }
                self.field_counts.push(count);
            }
        }
    }

    /// Pass 3: calculated field expressions.
    fn resolve_calcs(&mut self) {
        let ctx = &mut self.ctx;
        for item in &self.p.items {
            if let PacketItem::Calculated(c) = item
                && let Some(t) = ctx.check_expr(&c.expr, c.span)
            {
                let idx = ctx.names[&c.name];
                let target = match ctx.members[idx].ty {
                    ValueType::Float { .. } => Ty::Float,
                    _ => Ty::Int,
                };
                ctx.members[idx].kind = MemberKind::Calculated(coerce(t, target));
            }
        }
    }

    /// Pass 4: layout, alignment and decode order.
    fn lay_out(&mut self) {
        let p = self.p;
        let last_stored = p.items.iter().rposition(|it| matches!(it, PacketItem::Field(_) | PacketItem::Bitfield(_)));
        let mut field_no = 0usize;

        self.schedule_calcs();
        for (item_idx, item) in p.items.iter().enumerate() {
            match item {
                PacketItem::Calculated(_) => {}
                PacketItem::Align(bytes, span) => {
                    if self.open_ended {
                        self.ctx.diags.push(Diagnostic::new(
                            "`align` follows a field that consumes the rest of the input",
                            *span,
                        ));
                    }
                    self.cursor.pad_to(*bytes, &mut self.steps);
                }
                PacketItem::Field(f) => {
                    let count = self.field_counts[field_no].clone();
                    field_no += 1;
                    self.lay_out_field(f, count, Some(item_idx) == last_stored);
                }
                PacketItem::Bitfield(b) => self.lay_out_bitfield(b),
            }
            self.schedule_calcs();
        }

        // C-style tail padding: the size is a multiple of the packet's alignment.
        if p.align.is_some() && !self.open_ended {
            self.cursor.pad_to(self.alignment, &mut self.steps);
        }
    }

    fn schedule_calcs(&mut self) {
        self.ctx.schedule_calcs(&mut self.steps, &self.available, &mut self.scheduled);
    }

    /// Padding requested before a field: its explicit `align N`, and under
    /// `packet P align N` its natural alignment. None when nothing applies, so
    /// that packed bit fields are left alone.
    fn requested_padding(&mut self, t: &TypeNode, explicit: Option<u64>) -> Option<u64> {
        let mut a = explicit;
        if let Some(pack) = self.p.align {
            let n = natural_align(t, self.ctx.done).min(pack).max(1);
            self.alignment = self.alignment.max(n);
            if n > 1 {
                a = Some(a.unwrap_or(1).max(n));
            }
        }
        a
    }

    fn lay_out_field(&mut self, f: &TypeExpr, count: Option<Count>, is_last: bool) {
        let p = self.p;
        let member = if f.id == "_" { None } else { self.ctx.names.get(&f.id).copied() };
        let ty = field_value_type(f);
        if let Some(pad) = self.requested_padding(&f.expr, f.align) {
            self.cursor.pad_to(pad, &mut self.steps);
        }

        if self.open_ended {
            self.ctx.diags.push(Diagnostic::new(
                format!("field `{}` follows a field that consumes the rest of the input", f.id),
                f.span,
            ));
        }

        // Lengths must only use values already decoded.
        if let Some(Count::Expr(e)) = &count {
            self.ctx.require_available(e, &self.available, &self.scheduled, f.span, &f.id);
        }
        if matches!(count, Some(Count::Remaining)) {
            if !is_last {
                self.ctx.diags.push(
                    Diagnostic::new(
                        format!("`{}` has no length, so it must be the last field of `{}`", f.id, p.name),
                        f.span,
                    )
                    .with_note("give it a length such as bytes[len], or move it to the end"),
                );
            }
            self.open_ended = true;
        }

        if f.id == "_" && !matches!(ty, ValueType::Int { .. }) {
            self.ctx.diags.push(Diagnostic::new("padding (`_`) must have an integer or bytes type", f.span));
        }

        if let ValueType::Packet(name) = &ty {
            self.check_nested(f, name, count.is_some(), is_last);
        }

        let align = self.cursor.align;
        let codec = if ty == ValueType::Str {
            self.ctx.string_codec(f, &self.default_endian, align)
        } else {
            self.ctx.codec_for(&f.expr, f.endianness.clone(), &self.default_endian, align, f.span, &f.id)
        };
        let (elem_bits, elem_fixed) = match &codec {
            Codec::Packet(n) => {
                let nested = self.ctx.done.get(n);
                (nested.map(|x| x.min_bits).unwrap_or(0), nested.and_then(|x| x.fixed_bits))
            }
            Codec::Str(StrMode::Padded | StrMode::Exact) => (8, Some(8)),
            Codec::Str(StrMode::Prefixed { width, .. }) => (*width as u64, None),
            Codec::Str(StrMode::CString) => (8, None),
            c => (c.bits() as u64, Some(c.bits() as u64)),
        };
        // Advance alignment and the exact offset.
        match &count {
            None => self.cursor.advance(elem_bits, elem_fixed, 1),
            Some(Count::Expr(e)) => match e.const_int() {
                Some(n) if n >= 0 => self.cursor.advance(elem_bits, elem_fixed, n as u64),
                _ => self.cursor.advance_unknown(elem_bits.wrapping_mul(const_factor(e))),
            },
            Some(Count::Remaining) => self.cursor.advance_unknown(elem_bits),
        }

        self.steps.push(Step::Field { member, ty, codec, array: count });
        if let Some(m) = member {
            self.available.insert(m);
        }
    }

    /// Rules for a field whose type is another packet.
    fn check_nested(&mut self, f: &TypeExpr, name: &str, is_array: bool, is_last: bool) {
        if f.endianness.is_some() {
            self.ctx.diags.push(Diagnostic::new(
                format!("endianness on `{}` has no effect; set it on packet `{}` instead", f.id, name),
                f.span,
            ));
        }
        let Some(nested) = self.ctx.done.get(name) else { return };
        if nested.open_ended && (!is_last || is_array) {
            self.ctx.diags.push(Diagnostic::new(
                format!("packet `{}` consumes the rest of the input, so `{}` must be a single, last field", name, f.id),
                f.span,
            ));
        }
        if nested.open_ended {
            self.open_ended = true;
        }
        if is_array && nested.min_bits < 8 {
            self.ctx.diags.push(Diagnostic::new(
                format!("packet `{}` can be empty, so it cannot be used in the array `{}`", name, f.id),
                f.span,
            ));
        }
    }

    fn lay_out_bitfield(&mut self, b: &BitfieldExpr) {
        if self.open_ended {
            self.ctx.diags.push(Diagnostic::new(
                format!("field `{}` follows a field that consumes the rest of the input", b.id),
                b.span,
            ));
        }
        if let Some(pad) = self.requested_padding(&b.container, b.align) {
            self.cursor.pad_to(pad, &mut self.steps);
        }
        let (cwidth, _) = match b.container.integer_info() {
            Some(info) if !matches!(b.container, TypeNode::Bytes) => info,
            _ => {
                self.ctx.diags.push(Diagnostic::new(
                    format!("bitfield `{}` needs an integer container such as uint8 or u12", b.id),
                    b.span,
                ));
                (8, false)
            }
        };
        let align = self.cursor.align;
        let codec = self.ctx.codec_for(&b.container, b.endianness.clone(), &self.default_endian, align, b.span, &b.id);
        let total: u32 = b.members.iter().map(|m| m.width).sum();
        if total > cwidth {
            self.ctx.diags.push(Diagnostic::new(
                format!("bitfield `{}` members use {} bits but the container has only {}", b.id, total, cwidth),
                b.span,
            ));
        }
        let mut parts = Vec::new();
        let mut offset = 0u32;
        for m in &b.members {
            if m.name != "_" && total <= cwidth {
                let shift = match b.order {
                    BitOrder::Msb => cwidth - offset - m.width,
                    BitOrder::Lsb => offset,
                };
                if let Some(&idx) = self.ctx.names.get(&m.name) {
                    parts.push(BitPart { member: idx, shift, width: m.width, signed: m.signed });
                    self.available.insert(idx);
                }
            }
            offset += m.width;
        }
        self.cursor.advance(cwidth as u64, Some(cwidth as u64), 1);
        self.steps.push(Step::Bitfield { container: codec, container_width: cwidth, parts });
    }

    /// Pass 5: final checks, then the packet.
    fn finish(mut self) -> Result<Packet, Vec<Diagnostic>> {
        let p = self.p;
        // Calculated fields that could never be evaluated.
        for item in &p.items {
            if let PacketItem::Calculated(c) = item {
                let idx = self.ctx.names[&c.name];
                if !self.scheduled.contains(&idx) && self.ctx.diags.is_empty() {
                    self.ctx
                        .diags
                        .push(Diagnostic::new(format!("calculated field `{}` depends on itself", c.name), c.span));
                }
            }
        }

        let align = self.cursor.align;
        if !align.is_aligned() {
            if align.modulus == 8 {
                self.ctx.diags.push(
                    Diagnostic::new(
                        format!(
                            "packet `{}` ends {} bit(s) into a byte; packets must be a whole number of bytes",
                            p.name, align.offset
                        ),
                        p.span,
                    )
                    .with_note(format!("add `_ u{}` as padding at the end", 8 - align.offset)),
                );
            } else {
                self.ctx.diags.push(Diagnostic::new(
                    format!("the size of packet `{}` may not be a whole number of bytes", p.name),
                    p.span,
                ).with_note("a variable-length array of bit-sized elements must have a length whose bit count is a multiple of 8 (e.g. u12[n * 2])"));
            }
        }

        let encode_calcs = self.encode_calcs();
        if !self.ctx.diags.is_empty() {
            return Err(self.ctx.diags);
        }
        let fixed_bits = if self.open_ended { None } else { self.cursor.exact };
        Ok(Packet {
            name: p.name.clone(),
            members: self.ctx.members,
            steps: self.steps,
            encode_calcs,
            min_bits: self.cursor.min_bits,
            open_ended: self.open_ended,
            fixed_bits,
            alignment: if p.align.is_some() { self.alignment } else { 1 },
        })
    }

    /// Calculated members needed by encode (lengths depend on them), in decode order.
    fn encode_calcs(&self) -> Vec<usize> {
        let mut needed = HashSet::<usize>::new();
        let mut stack = Vec::new();
        for m in &self.ctx.members {
            if let Some(Count::Expr(e)) = &m.array {
                e.deps(&mut stack);
            }
        }
        while let Some(m) = stack.pop() {
            if let MemberKind::Calculated(e) = &self.ctx.members[m].kind
                && needed.insert(m)
            {
                e.deps(&mut stack);
            }
        }
        self.steps
            .iter()
            .filter_map(|s| match s {
                Step::Calc { member } if needed.contains(member) => Some(*member),
                _ => None,
            })
            .collect()
    }
}
