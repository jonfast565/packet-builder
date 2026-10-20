//! Frame lengths: when a packet's total size follows from a few header
//! fields at fixed offsets (FLAP: 6 header bytes plus `length`), a reader of
//! a byte stream can tell how many bytes one packet takes after reading only
//! the header. Wireshark's TCP reassembly and the streaming decoders use it.

use super::expr::{ArithOp, TExpr, Ty};
use super::model::{Module, Packet};
use super::wire::{Codec, Count, Step};

/// A header value the frame length depends on: `bits` bits at `shift` in
/// the `container_bits`-bit integer at `offset_bits` (shift 0 and the full
/// width for plain fields).
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderField {
    pub member: usize,
    pub offset_bits: u64,
    pub container: Codec,
    pub container_bits: u32,
    pub shift: u32,
    pub bits: u32,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameLength {
    /// Bytes needed before the length is known.
    pub header_bytes: u64,
    /// The header fields `total` may read, at fixed positions.
    pub fields: Vec<HeaderField>,
    /// Calculated members of the header, evaluated in order before `total`.
    pub calcs: Vec<usize>,
    /// The packet's size in bytes, an expression over those members.
    pub total: TExpr,
}

fn add(a: TExpr, b: TExpr) -> TExpr {
    TExpr::Arith { op: ArithOp::Add, a: Box::new(a), b: Box::new(b), ty: Ty::Int }
}

fn mul(a: TExpr, b: TExpr) -> TExpr {
    TExpr::Arith { op: ArithOp::Mul, a: Box::new(a), b: Box::new(b), ty: Ty::Int }
}

impl Module {
    /// How to find the size of `p` from its header, if it has a fixed-size
    /// header followed by at most one part whose size is a header expression
    /// (a `size n` window or an array `[n]` of fixed-size elements), then a
    /// fixed-size tail.
    pub fn frame_length(&self, p: &Packet) -> Option<FrameLength> {
        let fixed = |codec: &Codec| -> Option<u64> {
            match codec {
                Codec::Bytes { .. } | Codec::Bits { .. } | Codec::Float { .. } | Codec::Mac => {
                    Some(codec.bits() as u64)
                }
                Codec::Packet(r) => {
                    let nested = self.packets.iter().find(|x| x.name == r.name)?;
                    nested.fixed_bits
                }
                _ => None,
            }
        };
        let mut offset = 0u64;
        let mut fields = Vec::new();
        let mut calcs = Vec::new();
        let mut known: Vec<usize> = Vec::new();
        // The variable part: (bits before it, its size in bytes).
        let mut variable: Option<(u64, TExpr)> = None;
        let mut tail = 0u64;
        let uses_known = |e: &TExpr, known: &[usize]| {
            let mut deps = Vec::new();
            e.deps(&mut deps);
            deps.iter().all(|d| known.contains(d))
        };
        let mut i = 0;
        while i < p.steps.len() {
            let step = &p.steps[i];
            let grow = |n: u64, offset: &mut u64, tail: &mut u64, variable: &Option<(u64, TExpr)>| {
                if variable.is_some() { *tail += n } else { *offset += n }
            };
            match step {
                Step::Calc { member } => {
                    if variable.is_none()
                        && let Some(e) = p.members[*member].calc_expr()
                        && uses_known(e, &known)
                    {
                        calcs.push(*member);
                        known.push(*member);
                    }
                }
                Step::Assert { .. } | Step::At { .. } => {}
                Step::Align { bytes } => {
                    let unit = bytes * 8;
                    let pos = if variable.is_some() { None } else { Some(offset) };
                    let pad = (unit - pos? % unit) % unit;
                    grow(pad, &mut offset, &mut tail, &variable);
                }
                Step::Field { member, codec, array: None, ty } => {
                    let bits = fixed(codec)?;
                    if let (Some(m), None, Codec::Bytes { .. } | Codec::Bits { .. }) = (member, &variable, codec)
                        && matches!(ty, super::model::ValueType::Int { .. })
                    {
                        fields.push(HeaderField {
                            member: *m,
                            offset_bits: offset,
                            container: codec.clone(),
                            container_bits: bits as u32,
                            shift: 0,
                            bits: bits as u32,
                            signed: ty.is_signed(),
                        });
                        known.push(*m);
                    }
                    grow(bits, &mut offset, &mut tail, &variable);
                }
                Step::Bitfield { container, container_width, parts, .. } => {
                    if variable.is_none() {
                        for part in parts {
                            fields.push(HeaderField {
                                member: part.member,
                                offset_bits: offset,
                                container: container.clone(),
                                container_bits: *container_width,
                                shift: part.shift,
                                bits: part.width,
                                signed: part.signed,
                            });
                            known.push(part.member);
                        }
                    }
                    grow(*container_width as u64, &mut offset, &mut tail, &variable);
                }
                Step::Field { codec, array: Some(Count::Expr(e)), .. } => {
                    let elem = fixed(codec)?;
                    if variable.is_some() || !uses_known(e, &known) || !elem.is_multiple_of(8) {
                        return None;
                    }
                    variable = Some((offset, mul(e.clone(), TExpr::IntLit((elem / 8) as i64))));
                }
                Step::OpenWindow { size, .. } => {
                    if variable.is_some() || !uses_known(size, &known) {
                        return None;
                    }
                    variable = Some((offset, size.clone()));
                    // Whatever is inside takes exactly the window.
                    i = p.steps.iter().position(|s| matches!(s, Step::CloseWindow { open, .. } if *open == i))?;
                }
                _ => return None,
            }
            i += 1;
        }
        let (start, size) = variable.unwrap_or((offset, TExpr::IntLit(0)));
        if !start.is_multiple_of(8) || !tail.is_multiple_of(8) || p.open_ended {
            return None;
        }
        let header_bytes = start / 8;
        let total = add(TExpr::IntLit((header_bytes + tail / 8) as i64), size);
        Some(FrameLength { header_bytes, fields, calcs, total })
    }
}
