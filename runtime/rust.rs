// ---- packet-builder runtime -------------------------------------------------

/// What went wrong while decoding or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbErrorKind {
    /// The input ended before the packet did; `needed_bits` more would help.
    Incomplete,
    /// The data is malformed: a bad length, a missing terminator inside a
    /// window, nesting that is too deep, ...
    Invalid,
    /// A value does not fit in its field.
    Range,
    /// A string is not valid text, or contains a NUL where none is allowed.
    Text,
    /// A length, derived field or checksum does not match the data.
    Mismatch,
    /// A value breaks a declared constraint.
    Constraint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbError {
    pub kind: PbErrorKind,
    pub message: String,
    /// Where it happened: `Packet.field[index].field`.
    pub path: String,
    pub bit_offset: usize,
    /// For `Incomplete`: the least number of extra input bits needed.
    pub needed_bits: usize,
}

impl std::fmt::Display for PbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{} (at bit {})", self.message, self.bit_offset)
        } else {
            write!(f, "{}: {} (at bit {})", self.path, self.message, self.bit_offset)
        }
    }
}

impl std::error::Error for PbError {}

/// Nested packets deeper than this are rejected.
pub const PB_MAX_DEPTH: usize = 64;

/// The packets being decoded or encoded, innermost last, each with the field
/// it is working on: the path reported in errors.
#[derive(Debug, Clone, Default)]
struct PbTrace {
    frames: Vec<(&'static str, &'static str, Option<usize>)>,
}

impl PbTrace {
    fn enter(&mut self, packet: &'static str) -> bool {
        self.frames.push((packet, "", None));
        self.frames.len() <= PB_MAX_DEPTH
    }

    fn leave(&mut self) {
        self.frames.pop();
    }

    fn at(&mut self, field: &'static str) {
        if let Some(f) = self.frames.last_mut() {
            f.1 = field;
            f.2 = None;
        }
    }

    fn at_index(&mut self, index: usize) {
        if let Some(f) = self.frames.last_mut() {
            f.2 = Some(index);
        }
    }

    fn path(&self) -> String {
        let mut out = String::new();
        if let Some(first) = self.frames.first() {
            out.push_str(first.0);
        }
        for (_, field, index) in &self.frames {
            if field.is_empty() {
                break;
            }
            out.push('.');
            out.push_str(field);
            if let Some(i) = index {
                out.push_str(&format!("[{}]", i));
            }
        }
        out
    }
}

/// `"0a0b"`: bytes as a JSON string of hex digits (for `to_json`).
pub fn pb_json_hex(b: &[u8]) -> String {
    format!("\"{}\"", b.iter().map(|x| format!("{:02x}", x)).collect::<String>())
}

/// A JSON string literal (for `to_json`).
pub fn pb_json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Decoding from a buffer that may not hold the whole packet yet (a stream).
#[derive(Debug, Clone, PartialEq)]
pub enum PbStatus<T> {
    /// The value, and the bytes it took.
    Done(T, usize),
    /// At least this many more bytes are needed.
    Incomplete(usize),
}

/// Where a reader was before `PbReader::jump`.
pub struct PbJump {
    pos: usize,
    limit: usize,
    windows: usize,
}

// @versions{
/// `v` if it is one of the versions `min..=latest`.
fn pb_check_version(v: i64, min: u32, latest: u32) -> Result<u32, String> {
    if v < min as i64 || v > latest as i64 {
        return Err(format!("version {} is not one of the versions {}..{}", v, min, latest));
    }
    Ok(v as u32)
}
// @versions}

/// Reads integers of any bit width (MSB-first) and byte-aligned values.
pub struct PbReader<'a> {
    data: &'a [u8],
    pos: usize,   // in bits
    limit: usize, // end of the readable data in bits (a window inside `data`)
    windows: usize, // windows open
    trace: PbTrace,
    version: u32, // protocol version; 0 until set
}

impl<'a> PbReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        PbReader { data, pos: 0, limit: data.len() * 8, windows: 0, trace: PbTrace::default(), version: 0 }
    }

    // @versions{
    /// The protocol version (`version`), or `latest` while none is set.
    pub fn version_or(&self, latest: u32) -> i64 {
        (if self.version == 0 { latest } else { self.version }) as i64
    }

    /// Decode as protocol version `v`, which must be in `min..=latest`.
    pub fn set_version(&mut self, v: i64, min: u32, latest: u32) -> Result<(), PbError> {
        self.version = pb_check_version(v, min, latest).map_err(|m| self.error(PbErrorKind::Constraint, m))?;
        Ok(())
    }
    // @versions}

    pub fn position_bits(&self) -> usize {
        self.pos
    }

    pub fn remaining_bits(&self) -> usize {
        self.limit - self.pos
    }

    /// Whole bytes left before the end of the window or input (`remaining`).
    pub fn remaining_bytes(&self) -> i64 {
        (self.remaining_bits() / 8) as i64
    }

    /// Whether reads stop at the real end of the input (not at a window).
    fn at_top(&self) -> bool {
        self.windows == 0
    }

    pub fn error(&self, kind: PbErrorKind, message: String) -> PbError {
        PbError { kind, message, path: self.trace.path(), bit_offset: self.pos, needed_bits: 0 }
    }

    /// `bits` more bits are needed than are left.
    fn short(&self, bits: usize, what: &str) -> PbError {
        if self.at_top() {
            let mut e = self.error(
                PbErrorKind::Incomplete,
                format!("unexpected end of data: {} needs {} more bit(s), {} left", what, bits, self.remaining_bits()),
            );
            e.needed_bits = bits - self.remaining_bits();
            e
        } else {
            self.error(
                PbErrorKind::Invalid,
                format!("{} needs {} bit(s) but its window has {} left", what, bits, self.remaining_bits()),
            )
        }
    }

    fn need(&self, bits: usize) -> Result<(), PbError> {
        if bits > self.remaining_bits() { Err(self.short(bits, "the field")) } else { Ok(()) }
    }

    pub fn enter(&mut self, packet: &'static str) -> Result<(), PbError> {
        if self.trace.enter(packet) {
            Ok(())
        } else {
            Err(self.error(PbErrorKind::Invalid, format!("packets nested more than {} deep", PB_MAX_DEPTH)))
        }
    }

    pub fn leave(&mut self) {
        self.trace.leave();
    }

    pub fn at(&mut self, field: &'static str) {
        self.trace.at(field);
    }

    pub fn at_index(&mut self, index: usize) {
        self.trace.at_index(index);
    }

    /// Restrict reading to the next `bytes` bytes; returns the previous limit
    /// for `pop_limit`.
    pub fn push_limit(&mut self, bytes: i64) -> Result<usize, PbError> {
        if bytes < 0 {
            return Err(self.error(PbErrorKind::Invalid, format!("negative size {}", bytes)));
        }
        let bits = (bytes as u64).saturating_mul(8);
        if bits > self.remaining_bits() as u64 {
            return Err(self.short(bits as usize, "the window"));
        }
        let saved = self.limit;
        self.limit = self.pos + bits as usize;
        self.windows += 1;
        Ok(saved)
    }

    /// Skip what is left of the current window and restore `saved`; with
    /// `exact`, bytes left over are an error.
    pub fn pop_limit(&mut self, saved: usize, exact: bool) -> Result<(), PbError> {
        if exact && self.remaining_bits() > 0 {
            return Err(self.error(
                PbErrorKind::Invalid,
                format!("{} bit(s) left over in a field that must fill its size", self.remaining_bits()),
            ));
        }
        self.pos = self.limit;
        self.limit = saved;
        self.windows -= 1;
        Ok(())
    }

    /// Read from `offset` bytes after bit `from` (the packet start, or 0 for
    /// the start of the input) until `jump_back`; windows do not apply there.
    pub fn jump(&mut self, from: usize, offset: i64) -> Result<PbJump, PbError> {
        if offset < 0 || from % 8 != 0 {
            return Err(self.error(PbErrorKind::Invalid, format!("bad offset {} (from bit {})", offset, from)));
        }
        let target = (offset as u64).saturating_mul(8).saturating_add(from as u64);
        if target > self.data.len() as u64 * 8 {
            return Err(self.error(PbErrorKind::Invalid, format!("offset {} is past the end of the input", offset)));
        }
        let saved = PbJump { pos: self.pos, limit: self.limit, windows: self.windows };
        self.pos = target as usize;
        self.limit = self.data.len() * 8;
        self.windows = 0;
        Ok(saved)
    }

    /// Return to where `jump` left.
    pub fn jump_back(&mut self, saved: PbJump) {
        self.pos = saved.pos;
        self.limit = saved.limit;
        self.windows = saved.windows;
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
        Ok(self.read_slice(n)?.to_vec())
    }

    /// The next `n` bytes, borrowed from the input.
    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8], PbError> {
        self.need(n.saturating_mul(8))?;
        let start = self.pos >> 3;
        self.pos += n * 8;
        Ok(&self.data[start..start + n])
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

    /// Bytes up to (not including) a NUL terminator, which is consumed.
    pub fn read_cstring(&mut self) -> Result<Vec<u8>, PbError> {
        Ok(self.read_cstring_slice()?.to_vec())
    }

    /// The bytes before a NUL, borrowed; the NUL is consumed.
    pub fn read_cstring_slice(&mut self) -> Result<&'a [u8], PbError> {
        let start = self.pos >> 3;
        let data: &'a [u8] = self.data;
        match data[start..self.limit >> 3].iter().position(|b| *b == 0) {
            Some(n) => {
                self.pos += (n + 1) * 8;
                Ok(&data[start..start + n])
            }
            None => Err(self.short(self.remaining_bits() + 8, "the NUL-terminated string")),
        }
    }

    /// Validate a decoded element count against the data that is left.
    pub fn count(&self, n: i64, elem_bits: u64) -> Result<usize, PbError> {
        if n < 0 {
            return Err(self.error(PbErrorKind::Invalid, format!("negative length {}", n)));
        }
        if elem_bits > 0 && n as u64 > self.remaining_bits() as u64 / elem_bits {
            let bits = (n as u64).saturating_mul(elem_bits).min(usize::MAX as u64) as usize;
            return Err(self.short(bits, &format!("length {}", n)));
        }
        Ok(n as usize)
    }

    pub fn utf8(&self, raw: Vec<u8>) -> Result<String, PbError> {
        String::from_utf8(raw).map_err(|_| self.error(PbErrorKind::Text, "invalid UTF-8".into()))
    }

    /// Borrowed UTF-8 text; `padded` ends it at the first NUL.
    pub fn utf8_slice(&self, raw: &'a [u8], padded: bool) -> Result<&'a str, PbError> {
        let raw = if padded { &raw[..raw.iter().position(|b| *b == 0).unwrap_or(raw.len())] } else { raw };
        std::str::from_utf8(raw).map_err(|_| self.error(PbErrorKind::Text, "invalid UTF-8".into()))
    }

    /// Text in encoding `enc` (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
    /// 4 UTF-16BE); with `padded`, the text ends at the first NUL character.
    pub fn text(&self, raw: Vec<u8>, enc: u32, padded: bool) -> Result<String, PbError> {
        let bad = |what: &str| self.error(PbErrorKind::Text, format!("invalid {}", what));
        match enc {
            3 | 4 => {
                if raw.len() % 2 != 0 {
                    return Err(bad("UTF-16 (an odd number of bytes)"));
                }
                let mut units: Vec<u16> = raw
                    .chunks(2)
                    .map(|c| if enc == 3 { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
                    .collect();
                if padded && let Some(n) = units.iter().position(|u| *u == 0) {
                    units.truncate(n);
                }
                String::from_utf16(&units).map_err(|_| bad("UTF-16"))
            }
            _ => {
                let raw = if padded { pb_until_nul(raw) } else { raw };
                match enc {
                    1 if raw.iter().any(|b| *b >= 0x80) => Err(bad("ASCII")),
                    1 | 2 => Ok(raw.iter().map(|b| *b as char).collect()),
                    _ => String::from_utf8(raw).map_err(|_| bad("UTF-8")),
                }
            }
        }
    }

    /// One variable-length integer (`kind`: 0 uleb128, 1 sleb128, 2 zigzag,
    /// 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.
    pub fn read_varint(&mut self, kind: u32) -> Result<u64, PbError> {
        let too_long = |r: &Self| r.error(PbErrorKind::Invalid, "the varint does not fit in 64 bits".into());
        if kind == 5 {
            let first = self.read_uint(1, false)?;
            if first & 0x80 == 0 {
                return Ok(first);
            }
            return Ok(((first & 0x7f) << 8) | self.read_uint(1, false)?);
        }
        if kind == 4 {
            let first = self.read_uint(1, false)?;
            let n = 1u32 << (first >> 6);
            let mut v = first & 0x3f;
            if n > 1 {
                v = (v << (8 * (n - 1))) | self.read_uint(n - 1, false)?;
            }
            return Ok(v);
        }
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.read_uint(1, false)?;
            if kind == 3 {
                if v >> 57 != 0 {
                    return Err(too_long(self));
                }
                v = (v << 7) | (b & 0x7f);
            } else {
                // The 10th byte holds bit 63 only (and, for sleb128, its sign).
                let last_ok = if kind == 1 { b & 0x7f == 0 || b & 0x7f == 0x7f } else { b & 0x7e == 0 };
                if shift >= 64 || (shift == 63 && (b & 0x80 != 0 || !last_ok)) {
                    return Err(too_long(self));
                }
                v |= (b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if kind == 1 && shift < 64 && b & 0x40 != 0 {
                    v |= u64::MAX << shift;
                }
                break;
            }
        }
        if kind == 2 {
            v = (v >> 1) ^ (v & 1).wrapping_neg();
        }
        Ok(v)
    }

    /// Bytes up to `term`, which is consumed. Without it: the rest of the
    /// input when `optional`, otherwise an error.
    pub fn read_until(&mut self, term: &[u8], optional: bool) -> Result<Vec<u8>, PbError> {
        Ok(self.read_until_slice(term, optional)?.to_vec())
    }

    /// The bytes before `term`, borrowed (see `read_until`).
    pub fn read_until_slice(&mut self, term: &[u8], optional: bool) -> Result<&'a [u8], PbError> {
        let start = self.pos >> 3;
        let end = self.limit >> 3;
        let data: &'a [u8] = self.data;
        let window = &data[start..end];
        match window.windows(term.len()).position(|w| w == term) {
            Some(n) => {
                self.pos += (n + term.len()) * 8;
                Ok(&window[..n])
            }
            None if optional => {
                self.pos = self.limit;
                Ok(window)
            }
            None => Err(self.short(self.remaining_bits() + 8, "the terminated field")),
        }
    }

    /// Checksum `algo` of the input between two bit positions (whole bytes);
    /// the bytes between `hole_from` and `hole_to` count as zero.
    pub fn checksum(&self, algo: u32, from: usize, to: usize, hole_from: usize, hole_to: usize) -> u64 {
        pb_checksum(algo, self.data, from / 8, to / 8, hole_from / 8, hole_to / 8)
    }
}

/// Builds a byte buffer; integers may be written at any bit position.
#[derive(Default)]
pub struct PbWriter {
    buf: Vec<u8>,
    pos: usize, // in bits
    trace: PbTrace,
    /// Where `buf` goes in the output, in bits (non-zero for `sub` writers).
    base: usize,
    /// Packets placed at an offset (`at`): byte position, bytes and the
    /// field's path. `finish` writes them.
    placed: Vec<(usize, Vec<u8>, String)>,
    version: u32, // protocol version; 0 until set
}

impl PbWriter {
    pub fn new() -> Self {
        PbWriter::default()
    }

    // @versions{
    /// The protocol version (`version`), or `latest` while none is set.
    pub fn version_or(&self, latest: u32) -> i64 {
        (if self.version == 0 { latest } else { self.version }) as i64
    }

    /// Encode as protocol version `v`, which must be in `min..=latest`.
    pub fn set_version(&mut self, v: i64, min: u32, latest: u32) -> Result<(), PbError> {
        self.version = pb_check_version(v, min, latest).map_err(|m| self.error(PbErrorKind::Constraint, m))?;
        Ok(())
    }

    /// The version a value carries in-band: used unless one is set already.
    pub fn adopt_version(&mut self, v: i64, min: u32, latest: u32) -> Result<(), PbError> {
        if self.version == 0 { self.set_version(v, min, latest) } else { Ok(()) }
    }
    // @versions}

    pub fn position_bits(&self) -> usize {
        self.pos
    }

    pub fn error(&self, kind: PbErrorKind, message: String) -> PbError {
        PbError { kind, message, path: self.trace.path(), bit_offset: self.pos, needed_bits: 0 }
    }

    pub fn enter(&mut self, packet: &'static str) -> Result<(), PbError> {
        if self.trace.enter(packet) {
            Ok(())
        } else {
            Err(self.error(PbErrorKind::Invalid, format!("packets nested more than {} deep", PB_MAX_DEPTH)))
        }
    }

    pub fn leave(&mut self) {
        self.trace.leave();
    }

    pub fn at(&mut self, field: &'static str) {
        self.trace.at(field);
    }

    pub fn at_index(&mut self, index: usize) {
        self.trace.at_index(index);
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

    /// The output, with every placed packet written at its offset: past the
    /// end (zero-filling the gap), or over bytes that must already match.
    pub fn finish(mut self) -> Result<Vec<u8>, PbError> {
        let mut placed = std::mem::take(&mut self.placed);
        placed.sort_by_key(|p| p.0);
        for (at, bytes, path) in placed {
            // The output reaches the offset even when the packet is empty.
            if self.buf.len() < at {
                self.buf.resize(at, 0);
            }
            for (i, b) in bytes.into_iter().enumerate() {
                let k = at + i;
                if k < self.buf.len() {
                    if self.buf[k] != b {
                        return Err(PbError {
                            kind: PbErrorKind::Mismatch,
                            message: format!("the packet placed at byte {} does not match the bytes already there", at),
                            path,
                            bit_offset: k * 8,
                            needed_bits: 0,
                        });
                    }
                } else {
                    self.buf.resize(k, 0);
                    self.buf.push(b);
                }
            }
        }
        Ok(self.buf)
    }

    /// A writer for a packet placed `offset` bytes after bit `from` of this
    /// writer (the packet start), or after the start of the output (`root`).
    pub fn sub(&self, from: usize, offset: i64, root: bool) -> Result<PbWriter, PbError> {
        let start = if root { 0 } else { self.base + from };
        if offset < 0 || start % 8 != 0 {
            return Err(self.error(PbErrorKind::Range, format!("bad offset {} (from bit {})", offset, start)));
        }
        let base = (offset as usize).saturating_mul(8).saturating_add(start);
        Ok(PbWriter { base, trace: self.trace.clone(), version: self.version, ..PbWriter::default() })
    }

    /// Keep what `sub` wrote, for `finish`.
    pub fn place(&mut self, sub: PbWriter) {
        self.placed.push((sub.base / 8, sub.buf, self.trace.path()));
        self.placed.extend(sub.placed);
    }

    /// End a window of `size` bytes that started at bit `start`: the content
    /// must fit (and fill it when `exact`); the rest is zero-filled.
    pub fn end_window(&mut self, start: usize, size: i64, exact: bool) -> Result<(), PbError> {
        let used = self.pos - start;
        let room = (size.max(0) as usize).saturating_mul(8);
        if size < 0 || used > room {
            return Err(self.error(
                PbErrorKind::Range,
                format!("the content takes {} bit(s), more than its size of {} byte(s)", used, size),
            ));
        }
        if exact && used != room {
            return Err(self.error(
                PbErrorKind::Mismatch,
                format!("the content takes {} bit(s) but must fill its {} byte(s)", used, size),
            ));
        }
        self.write_zero_bits(room - used);
        Ok(())
    }

    /// Overwrite `nbytes` bytes at bit position `at` (byte aligned).
    pub fn patch_uint(&mut self, at: usize, value: u64, nbytes: u32, little: bool) {
        for i in 0..nbytes {
            let shift = if little { 8 * i } else { 8 * (nbytes - 1 - i) };
            self.buf[at / 8 + i as usize] = (value >> shift) as u8;
        }
    }

    /// Overwrite `width` bits at bit position `at`, MSB first.
    pub fn patch_bits(&mut self, at: usize, value: u64, width: u32) {
        for i in 0..width as usize {
            let bit = ((value >> (width as usize - 1 - i)) & 1) as u8;
            let (byte, off) = ((at + i) / 8, 7 - (at + i) % 8);
            self.buf[byte] = (self.buf[byte] & !(1 << off)) | (bit << off);
        }
    }

    /// Checksum `algo` of the output between two bit positions (whole
    /// bytes); the bytes between `hole_from` and `hole_to` count as zero.
    pub fn checksum(&self, algo: u32, from: usize, to: usize, hole_from: usize, hole_to: usize) -> u64 {
        pb_checksum(algo, &self.buf, from / 8, to / 8, hole_from / 8, hole_to / 8)
    }

    /// One variable-length integer (see `PbReader::read_varint`).
    pub fn write_varint(&mut self, kind: u32, value: u64) -> Result<(), PbError> {
        match kind {
            5 => {
                if value > 0x7fff {
                    return Err(self.error(PbErrorKind::Range, format!("{} does not fit in a varint15", value)));
                }
                if value < 0x80 {
                    self.write_uint(value, 1, false);
                } else {
                    self.write_uint(value | 0x8000, 2, false);
                }
            }
            4 => {
                let n: u32 = match value {
                    0..=0x3f => 1,
                    0x40..=0x3fff => 2,
                    0x4000..=0x3fff_ffff => 4,
                    0x4000_0000..=0x3fff_ffff_ffff_ffff => 8,
                    _ => {
                        return Err(self.error(PbErrorKind::Range, format!("{} does not fit in a QUIC varint", value)));
                    }
                };
                self.write_uint(value | ((n.trailing_zeros() as u64) << (8 * n - 2)), n, false);
            }
            1 => {
                let mut v = value as i64;
                loop {
                    let b = (v & 0x7f) as u64;
                    v >>= 7;
                    let done = (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0);
                    self.write_uint(if done { b } else { b | 0x80 }, 1, false);
                    if done {
                        break;
                    }
                }
            }
            3 => {
                let mut groups = vec![value & 0x7f];
                let mut v = value >> 7;
                while v != 0 {
                    groups.push((v & 0x7f) | 0x80);
                    v >>= 7;
                }
                for g in groups.iter().rev() {
                    self.write_uint(*g, 1, false);
                }
            }
            _ => {
                let mut v = if kind == 2 { (value << 1) ^ (((value as i64) >> 63) as u64) } else { value };
                loop {
                    let b = v & 0x7f;
                    v >>= 7;
                    self.write_uint(if v != 0 { b | 0x80 } else { b }, 1, false);
                    if v == 0 {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// The bytes of `s` in encoding `enc` (see `PbReader::text`).
    pub fn text(&self, s: &str, enc: u32) -> Result<Vec<u8>, PbError> {
        match enc {
            1 | 2 => {
                let max = if enc == 1 { 0x7f } else { 0xff };
                s.chars()
                    .map(|c| if (c as u32) <= max { Ok(c as u8) } else { Err(c) })
                    .collect::<Result<Vec<u8>, char>>()
                    .map_err(|c| self.error(PbErrorKind::Text, format!("{:?} is not {}", c, if enc == 1 { "ASCII" } else { "Latin-1" })))
            }
            3 => Ok(s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()),
            4 => Ok(s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()),
            _ => Ok(s.as_bytes().to_vec()),
        }
    }

    /// A terminated value must not contain its terminator.
    pub fn check_no_term(&self, bytes: &[u8], term: &[u8]) -> Result<(), PbError> {
        if bytes.windows(term.len()).any(|w| w == term) {
            return Err(self.error(PbErrorKind::Invalid, "the value contains its terminator".into()));
        }
        Ok(())
    }

    pub fn check_fits(&self, len: usize, size: i64) -> Result<(), PbError> {
        if size < 0 || len as u64 > size as u64 {
            return Err(self.error(PbErrorKind::Range, format!("{} byte(s) do not fit in {}", len, size)));
        }
        Ok(())
    }

    pub fn check_no_nul(&self, bytes: &[u8]) -> Result<(), PbError> {
        if bytes.contains(&0) {
            return Err(self.error(PbErrorKind::Text, "the string contains a NUL byte".into()));
        }
        Ok(())
    }

    pub fn check_len(&self, actual: usize, expected: i64) -> Result<(), PbError> {
        if expected < 0 || actual as u64 != expected as u64 {
            return Err(self.error(
                PbErrorKind::Mismatch,
                format!("{} element(s) but the length expression says {}", actual, expected),
            ));
        }
        Ok(())
    }

    pub fn check_u(&self, v: u64, width: u32) -> Result<(), PbError> {
        if width < 64 && v >> width != 0 {
            return Err(self.error(PbErrorKind::Range, format!("value {} does not fit in {} bit(s)", v, width)));
        }
        Ok(())
    }

    pub fn check_i(&self, v: i64, width: u32) -> Result<(), PbError> {
        if width < 64 {
            let lo = -(1i64 << (width - 1));
            let hi = (1i64 << (width - 1)) - 1;
            if v < lo || v > hi {
                return Err(
                    self.error(PbErrorKind::Range, format!("value {} does not fit in {} signed bit(s)", v, width))
                );
            }
        }
        Ok(())
    }
}

/// CRC parameters by algorithm number: width, polynomial (reflected for
/// reflected CRCs), initial value, reflected, final XOR.
const PB_CRC: [(u32, u64, u64, bool, u64); 8] = [
    (8, 0x07, 0, false, 0),                             // crc8 (CRC-8/SMBUS)
    (16, 0xa001, 0, true, 0),                           // crc16_arc
    (16, 0x1021, 0xffff, false, 0),                     // crc16_ccitt_false (CRC-16/IBM-3740)
    (16, 0x1021, 0, false, 0),                          // crc16_xmodem
    (16, 0x8408, 0, true, 0),                           // crc16_kermit
    (16, 0xa001, 0xffff, true, 0),                      // crc16_modbus
    (32, 0xedb88320, 0xffffffff, true, 0xffffffff),     // crc32 (CRC-32/ISO-HDLC)
    (32, 0x82f63b78, 0xffffffff, true, 0xffffffff),     // crc32c (CRC-32/ISCSI)
];

/// Checksum `algo` of `buf[from..to]`, with `buf[hole_from..hole_to]` as
/// zeros. 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8,
/// 12: sum16, 13: sum32_fold16.
fn pb_checksum(algo: u32, buf: &[u8], from: usize, to: usize, hole_from: usize, hole_to: usize) -> u64 {
    let bytes = (from..to).map(|i| if i >= hole_from && i < hole_to { 0u64 } else { buf[i] as u64 });
    match algo {
        0..=7 => {
            let (width, poly, init, reflected, xorout) = PB_CRC[algo as usize];
            let mask = (1u64 << width) - 1;
            let mut crc = init;
            for b in bytes {
                if reflected {
                    crc ^= b;
                    for _ in 0..8 {
                        crc = if crc & 1 != 0 { (crc >> 1) ^ poly } else { crc >> 1 };
                    }
                } else {
                    crc ^= b << (width - 8);
                    for _ in 0..8 {
                        crc = (if crc & (1 << (width - 1)) != 0 { (crc << 1) ^ poly } else { crc << 1 }) & mask;
                    }
                }
            }
            (crc ^ xorout) & mask
        }
        8 => {
            let mut sum = 0u64;
            for (i, b) in bytes.enumerate() {
                sum += if i % 2 == 0 { b << 8 } else { b };
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !sum & 0xffff
        }
        9 => {
            let (mut a, mut b) = (0u64, 0u64);
            for x in bytes {
                a = (a + x) % 255;
                b = (b + a) % 255;
            }
            (b << 8) | a
        }
        10 => bytes.fold(0, |acc, b| (acc + b) & 0xff),
        12 => bytes.fold(0, |acc, b| (acc + b) & 0xffff),
        13 => {
            let mut sum = 0u64;
            for (i, b) in bytes.enumerate() {
                sum = (sum + (b << (8 * (3 - i % 4)))) & 0xffff_ffff;
            }
            ((sum >> 16) + (sum & 0xffff)) & 0xffff
        }
        _ => bytes.fold(0, |acc, b| acc ^ b),
    }
}

/// Padding needed after `offset` bits to reach a multiple of `unit` bits.
fn pb_pad(offset: usize, unit: usize) -> usize {
    (unit - offset % unit) % unit
}

fn pb_until_nul(mut raw: Vec<u8>) -> Vec<u8> {
    if let Some(n) = raw.iter().position(|b| *b == 0) {
        raw.truncate(n);
    }
    raw
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

fn pb_mod(a: i64, b: i64) -> i64 {
    if b == 0 { 0 } else { a.wrapping_rem(b) }
}

fn pb_shl(a: i64, b: i64) -> i64 {
    if (0..64).contains(&b) { a.wrapping_shl(b as u32) } else { 0 }
}

fn pb_shr(a: i64, b: i64) -> i64 {
    if b < 0 { 0 } else { a >> b.min(63) }
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

// ---- generated packets ------------------------------------------------------
