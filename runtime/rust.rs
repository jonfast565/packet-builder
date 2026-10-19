// ---- packet-builder runtime -------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbError(pub String);

impl std::fmt::Display for PbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PbError {}

/// Reads integers of any bit width (MSB-first) and byte-aligned values.
pub struct PbReader<'a> {
    data: &'a [u8],
    pos: usize, // in bits
}

impl<'a> PbReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        PbReader { data, pos: 0 }
    }

    pub fn position_bits(&self) -> usize {
        self.pos
    }

    pub fn remaining_bits(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    fn need(&self, bits: usize) -> Result<(), PbError> {
        if bits > self.remaining_bits() {
            return Err(PbError(format!(
                "unexpected end of data: need {} more bit(s) at bit offset {}, have {}",
                bits, self.pos, self.remaining_bits()
            )));
        }
        Ok(())
    }

    pub fn read_bits(&mut self, width: u32) -> Result<u64, PbError> {
        self.need(width as usize)?;
        let mut v: u64 = 0;
        let mut left = width;
        while left > 0 {
            let byte = self.data[self.pos >> 3];
            let off = (self.pos & 7) as u32;
            let take = (8 - off).min(left);
            let bits = (byte >> (8 - off - take)) & ((1u16 << take) - 1) as u8;
            v = (v << take) | bits as u64;
            self.pos += take as usize;
            left -= take;
        }
        Ok(v)
    }

    pub fn read_uint(&mut self, nbytes: u32, little: bool) -> Result<u64, PbError> {
        self.need(nbytes as usize * 8)?;
        let start = self.pos >> 3;
        let mut v: u64 = 0;
        for i in 0..nbytes as usize {
            let b = if little { self.data[start + nbytes as usize - 1 - i] } else { self.data[start + i] };
            v = (v << 8) | b as u64;
        }
        self.pos += nbytes as usize * 8;
        Ok(v)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, PbError> {
        self.need(n.saturating_mul(8))?;
        let start = self.pos >> 3;
        self.pos += n * 8;
        Ok(self.data[start..start + n].to_vec())
    }

    pub fn read_mac(&mut self) -> Result<[u8; 6], PbError> {
        let b = self.read_bytes(6)?;
        Ok([b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    pub fn skip_bits(&mut self, bits: usize) -> Result<(), PbError> {
        self.need(bits)?;
        self.pos += bits;
        Ok(())
    }
}

/// Builds a byte buffer; integers may be written at any bit position.
#[derive(Default)]
pub struct PbWriter {
    buf: Vec<u8>,
    pos: usize, // in bits
}

impl PbWriter {
    pub fn new() -> Self {
        PbWriter::default()
    }

    pub fn write_bits(&mut self, value: u64, width: u32) {
        let mut left = width;
        while left > 0 {
            if self.pos & 7 == 0 {
                self.buf.push(0);
            }
            let off = (self.pos & 7) as u32;
            let take = (8 - off).min(left);
            let bits = ((value >> (left - take)) & ((1u64 << take) - 1)) as u8;
            let last = self.buf.len() - 1;
            self.buf[last] |= bits << (8 - off - take);
            self.pos += take as usize;
            left -= take;
        }
    }

    pub fn write_uint(&mut self, value: u64, nbytes: u32, little: bool) {
        for i in 0..nbytes {
            let shift = if little { 8 * i } else { 8 * (nbytes - 1 - i) };
            self.buf.push((value >> shift) as u8);
        }
        self.pos += nbytes as usize * 8;
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.pos += data.len() * 8;
    }

    pub fn write_zero_bits(&mut self, bits: usize) {
        for _ in 0..bits / 32 {
            self.write_bits(0, 32);
        }
        self.write_bits(0, (bits % 32) as u32);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn pb_sext(v: u64, width: u32) -> i64 {
    if width >= 64 {
        v as i64
    } else if (v >> (width - 1)) & 1 == 1 {
        (v | (u64::MAX << width)) as i64
    } else {
        v as i64
    }
}

fn pb_trunc(v: i64, width: u32, signed: bool) -> i64 {
    if width >= 64 {
        return v;
    }
    let u = (v as u64) & ((1u64 << width) - 1);
    if signed { pb_sext(u, width) } else { u as i64 }
}

fn pb_div(a: i64, b: i64) -> i64 {
    if b == 0 { 0 } else { a.wrapping_div(b) }
}

fn pb_pow(base: i64, exp: i64) -> i64 {
    if exp < 0 {
        return 0;
    }
    let (mut base, mut exp, mut acc) = (base, exp as u64, 1i64);
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc.wrapping_mul(base);
        }
        base = base.wrapping_mul(base);
        exp >>= 1;
    }
    acc
}

/// Validate a decoded element count against the data that is left.
fn pb_count(n: i64, elem_bits: u64, r: &PbReader, field: &str) -> Result<usize, PbError> {
    if n < 0 {
        return Err(PbError(format!("negative length {} for field `{}`", n, field)));
    }
    if elem_bits > 0 && n as u64 > r.remaining_bits() as u64 / elem_bits {
        return Err(PbError(format!(
            "length {} for field `{}` exceeds the remaining data", n, field
        )));
    }
    Ok(n as usize)
}

fn pb_check_len(actual: usize, expected: i64, field: &str) -> Result<(), PbError> {
    if expected < 0 || actual as u64 != expected as u64 {
        return Err(PbError(format!(
            "field `{}` has {} element(s) but its length expression says {}", field, actual, expected
        )));
    }
    Ok(())
}

fn pb_check_u(v: u64, width: u32, field: &str) -> Result<(), PbError> {
    if width < 64 && v >> width != 0 {
        return Err(PbError(format!("value {} does not fit in {} bit(s) for field `{}`", v, width, field)));
    }
    Ok(())
}

fn pb_check_i(v: i64, width: u32, field: &str) -> Result<(), PbError> {
    if width < 64 {
        let lo = -(1i64 << (width - 1));
        let hi = (1i64 << (width - 1)) - 1;
        if v < lo || v > hi {
            return Err(PbError(format!("value {} does not fit in {} signed bit(s) for field `{}`", v, width, field)));
        }
    }
    Ok(())
}

// ---- generated packets ------------------------------------------------------
