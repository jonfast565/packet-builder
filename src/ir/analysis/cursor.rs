//! What is known about the bit offset while laying out a packet's fields.

use crate::ir::expr::{ArithOp, TExpr};
use crate::ir::model::Step;

/// What is known about the current bit offset: it is congruent to `offset`
/// modulo `modulus` (a divisor of 8). Byte aligned means `offset == 0` with
/// `modulus == 8`; variable-length arrays of bit-sized elements weaken the
/// modulus (e.g. `u12[n]` leaves the offset known only modulo 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Align {
    pub offset: u32,
    pub modulus: u32,
}

impl Align {
    pub const START: Align = Align { offset: 0, modulus: 8 };

    pub fn is_aligned(&self) -> bool {
        self.modulus == 8 && self.offset == 0
    }

    /// Advance by a fixed number of bits.
    fn advance(self, bits: u64) -> Align {
        Align { offset: ((self.offset as u64 + bits) % self.modulus as u64) as u32, modulus: self.modulus }
    }

    /// Advance by an unknown multiple of `step` bits.
    fn advance_multiple(self, step: u64) -> Align {
        let modulus = gcd(self.modulus as u64, step) as u32;
        Align { offset: self.offset % modulus, modulus }
    }

    pub fn describe(&self) -> String {
        if self.modulus == 8 {
            format!("{} bit(s) into a byte", self.offset)
        } else {
            "at a bit offset that depends on the data".to_string()
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// A constant factor of an integer expression (`n * 2` → 2), 1 if unknown.
pub(super) fn const_factor(e: &TExpr) -> u64 {
    match e {
        TExpr::IntLit(v) => v.unsigned_abs(),
        TExpr::Arith { op: ArithOp::Mul, a, b, .. } => const_factor(a).wrapping_mul(const_factor(b)),
        TExpr::Convert { e, .. } => const_factor(e),
        _ => 1,
    }
}

/// Position of the next field relative to the packet start.
#[derive(Debug, Clone, Copy)]
pub(super) struct Cursor {
    pub align: Align,
    /// Exact bit offset while it does not depend on the data.
    pub exact: Option<u64>,
    /// Smallest possible offset in bits.
    pub min_bits: u64,
}

impl Cursor {
    pub const START: Cursor = Cursor { align: Align::START, exact: Some(0), min_bits: 0 };

    /// Insert an alignment step unless the offset is known to be aligned already.
    pub fn pad_to(&mut self, bytes: u64, steps: &mut Vec<Step>) {
        if bytes <= 1 && self.align.is_aligned() {
            return;
        }
        let bits = bytes * 8;
        if let Some(x) = self.exact {
            let pad = (bits - x % bits) % bits;
            if pad == 0 {
                return;
            }
            self.exact = Some(x + pad);
            self.min_bits += pad;
        }
        steps.push(Step::Align { bytes });
        self.align = Align::START;
    }

    /// Advance past `n` elements of at least `elem_bits` bits each (exactly
    /// `elem_fixed` bits when the element size does not depend on the data).
    pub fn advance(&mut self, elem_bits: u64, elem_fixed: Option<u64>, n: u64) {
        self.min_bits += elem_bits * n;
        self.align = self.align.advance(elem_bits.wrapping_mul(n));
        self.exact = self.exact.and_then(|x| elem_fixed.map(|b| x + b * n));
    }

    /// Advance by an unknown multiple of `step` bits.
    pub fn advance_unknown(&mut self, step: u64) {
        self.align = self.align.advance_multiple(step);
        self.exact = None;
    }
}
