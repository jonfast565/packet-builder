//! Walking a packet's wire steps. Every backend's decoder and encoder
//! implements [`StepEmitter`]; [`StepEmitter::emit_steps`] is the shared
//! template that dispatches each [`Step`] to the matching hook.

use super::out::Out;
use crate::ir::{BitPart, Check, Codec, Count, Mark, Member, Packet, Step, StrMode, TExpr, ValueType};

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

    /// Record which field the following statements read or write, so errors
    /// can name it (`pb_r.at("length")`).
    fn locate(&self, out: &mut Out, field: &str);

    /// Fail with a `constraint` error unless `cond` holds (field checks and
    /// `assert`).
    fn check(&self, out: &mut Out, cond: &TExpr, message: &str);

    /// True for encoders: field checks run before a field is written rather
    /// than after it is read.
    fn encoding(&self) -> bool {
        false
    }

    /// Record the current bit position in the variable of `mark`
    /// (`common::mark_var`).
    fn mark(&self, out: &mut Out, mark: Mark);

    /// Decoders: fail with a `mismatch` error unless derived member `m`
    /// holds `value`.
    fn verify(&self, _out: &mut Out, _m: &Member, _value: &TExpr) {}

    /// Encoders: define the local `pbc_<name>` holding an encode-time value:
    /// a calculated member (in its type) or a derived one (as i64).
    fn define_local(&self, _out: &mut Out, _m: &Member, _value: &TExpr) {}

    /// Encoders: range-check derived member `m`'s local and write it, or
    /// patch it over the placeholder written at `at`.
    fn write_derived(&self, _out: &mut Out, _m: &Member, _codec: &Codec, _at: Option<Mark>) {}

    /// The wire name of a step's field (`_` for padding), if it has one.
    fn step_field<'s>(&'s self, step: &'s Step) -> Option<&'s str> {
        match step {
            Step::Field { member: Some(mi), .. } => Some(&self.packet().members[*mi].name),
            Step::Field { member: None, .. } => Some("_"),
            Step::Bitfield { name, .. } => Some(name),
            Step::Assert { .. } => Some(""),
            Step::Calc { .. } | Step::Align { .. } => None,
        }
    }

    /// The enforced checks of the members a step reads or writes. Encoders
    /// check members derived from the encoded bytes when they patch them.
    fn step_checks<'s>(&'s self, step: &'s Step) -> Vec<&'s Check> {
        let p = self.packet();
        let late = |m: &usize| self.encoding() && p.patches.contains(m);
        match step {
            Step::Field { member: Some(mi), array: None, .. } if !late(mi) => {
                p.members[*mi].enforced_checks().iter().collect()
            }
            Step::Bitfield { parts, .. } => parts.iter().flat_map(|b| p.members[b.member].enforced_checks()).collect(),
            _ => Vec::new(),
        }
    }

    fn emit_step(&self, out: &mut Out, step: &Step) {
        let members = &self.packet().members;
        if let Some(field) = self.step_field(step) {
            self.locate(out, field);
        }
        let checks = self.step_checks(step);
        if self.encoding() {
            for c in &checks {
                self.check(out, &c.cond, &c.message);
            }
        }
        match step {
            Step::Assert { index } => {
                let a = &self.packet().asserts[*index];
                // An assertion over values only known after encoding the
                // body is checked by decoders only.
                if !(self.encoding() && self.packet().depends_on_wire(&a.cond)) {
                    self.check(out, &a.cond, &a.message)
                }
            }
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
            Step::Field { member: Some(mi), codec, array: None, .. }
                if self.encoding() && self.packet().patches.contains(mi) =>
            {
                // A placeholder, patched after the last step.
                self.padding(out, codec, None)
            }
            Step::Field { member: Some(mi), codec, array: None, .. }
                if self.encoding() && members[*mi].is_derived() =>
            {
                self.write_derived(out, &members[*mi], codec, None)
            }
            Step::Field { member: Some(mi), ty, codec, array: None } => self.scalar(out, &members[*mi], ty, codec),
            Step::Field { member: Some(mi), ty, codec, array: Some(count) } => {
                self.array(out, &members[*mi], ty, codec, count)
            }
            Step::Bitfield { container, container_width, parts, .. } => {
                self.bitfield(out, container, *container_width, parts)
            }
        }
        if !self.encoding() {
            for c in &checks {
                self.check(out, &c.cond, &c.message);
            }
        }
    }

    /// Every step, with the marks derived fields need; then encoders patch
    /// the fields derived from the encoded bytes and decoders verify every
    /// derived field.
    fn emit_steps(&self, out: &mut Out) {
        let p = self.packet();
        let marks = p.marks(self.encoding());
        for (i, step) in p.steps.iter().enumerate() {
            if marks.contains(&Mark::Before(i)) {
                self.mark(out, Mark::Before(i));
            }
            self.emit_step(out, step);
            if marks.contains(&Mark::After(i)) {
                self.mark(out, Mark::After(i));
            }
        }
        if marks.contains(&Mark::PacketEnd) {
            self.mark(out, Mark::PacketEnd);
        }
        if self.encoding() {
            for &mi in &p.patches {
                let m = &p.members[mi];
                let (Some(si), Some(e)) = (p.field_step(mi), m.derived_expr()) else { continue };
                let Step::Field { codec, .. } = &p.steps[si] else { continue };
                self.locate(out, &m.name);
                self.define_local(out, m, e);
                for c in m.enforced_checks() {
                    self.check(out, &c.cond, &c.message);
                }
                self.write_derived(out, m, codec, Some(Mark::Before(si)));
            }
        } else {
            for &mi in &p.derived {
                let m = &p.members[mi];
                if let (false, Some(e)) = (m.lenient, m.derived_expr()) {
                    self.locate(out, &m.name);
                    self.verify(out, m, e);
                }
            }
        }
    }
}

/// Mask of the low `width` bits.
pub fn mask(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
}

/// Element type of a string's length prefix as written by the encoders.
pub const PREFIX_LEN: ValueType = ValueType::Int { width: 64, signed: false };
