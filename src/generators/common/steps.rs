//! Walking a packet's wire steps. Every backend's decoder and encoder
//! implements [`StepEmitter`]; [`StepEmitter::emit_steps`] is the shared
//! template that dispatches each [`Step`] to the matching hook.

use super::out::Out;
use crate::ir::{BitPart, Codec, Count, Member, Packet, Step, StrMode, TExpr, ValueType};

/// One hook per kind of wire step.
pub trait StepEmitter {
    fn packet(&self) -> &Packet;

    /// Skip (decode) or zero-fill (encode) to a multiple of `bytes` from the packet start.
    fn align(&self, out: &mut Out, bytes: u64);

    /// Evaluate a calculated member. Encoders keep the default: calculated
    /// members are not on the wire.
    fn calc(&self, _out: &mut Out, _member: &Member, _expr: &TExpr) {}

    /// A string member; `array` is its byte count for `Padded` and `Exact`.
    fn string(&self, out: &mut Out, member: &Member, mode: &StrMode, array: Option<&Count>);

    /// Padding (`_`) of `codec`-sized elements.
    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>);

    /// A single stored value.
    fn scalar(&self, out: &mut Out, member: &Member, ty: &ValueType, codec: &Codec);

    /// An array member (byte arrays included).
    fn array(&self, out: &mut Out, member: &Member, ty: &ValueType, codec: &Codec, count: &Count);

    /// An integer container split into sub-fields.
    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]);

    fn emit_step(&self, out: &mut Out, step: &Step) {
        let members = &self.packet().members;
        match step {
            Step::Align { bytes } => self.align(out, *bytes),
            Step::Calc { member } => {
                let m = &members[*member];
                if let Some(e) = m.calc_expr() {
                    self.calc(out, m, e);
                }
            }
            Step::Field { member: Some(mi), codec: Codec::Str(mode), array, .. } => {
                self.string(out, &members[*mi], mode, array.as_ref())
            }
            Step::Field { member: None, codec, array, .. } => self.padding(out, codec, array.as_ref()),
            Step::Field { member: Some(mi), ty, codec, array: None } => self.scalar(out, &members[*mi], ty, codec),
            Step::Field { member: Some(mi), ty, codec, array: Some(count) } => {
                self.array(out, &members[*mi], ty, codec, count)
            }
            Step::Bitfield { container, container_width, parts } => {
                self.bitfield(out, container, *container_width, parts)
            }
        }
    }

    fn emit_steps(&self, out: &mut Out) {
        for step in &self.packet().steps {
            self.emit_step(out, step);
        }
    }
}

/// Mask of the low `width` bits.
pub fn mask(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
}

/// Element type of a string's length prefix as written by the encoders.
pub const PREFIX_LEN: ValueType = ValueType::Int { width: 64, signed: false };
