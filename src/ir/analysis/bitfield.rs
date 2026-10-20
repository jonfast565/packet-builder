//! Bitfields: an integer container split into named sub-fields.

use super::packet::PacketBuilder;
use crate::ast::{BitOrder, BitfieldExpr, TypeNode};
use crate::errors::Diagnostic;
use crate::ir::model::{BitPart, Step};

impl PacketBuilder<'_> {
    pub(super) fn lay_out_bitfield(&mut self, b: &BitfieldExpr) {
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
        self.aligned_before = align.is_aligned();
        self.steps.push(Step::Bitfield { name: b.id.clone(), container: codec, container_width: cwidth, parts });
    }
}
