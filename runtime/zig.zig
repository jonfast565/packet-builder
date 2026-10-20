// ---- packet-builder runtime -------------------------------------------------

/// Incomplete: the input ended before the packet did. Invalid: malformed
/// data (a bad length, nesting too deep, ...). Range: a value does not fit
/// in its field. InvalidText: a string is not valid text. Mismatch: a length,
/// derived field or checksum does not match the data. Constraint: a value
/// breaks a declared constraint. The reader or writer's `trace.diag` says
/// where the first one happened.
pub const PbError = error{ Incomplete, Invalid, Range, InvalidText, Mismatch, Constraint, OutOfMemory };

/// The deepest packet nesting accepted.
pub const PB_MAX_DEPTH = 64;

pub const PbFrame = struct {
    packet: []const u8 = "",
    field: []const u8 = "",
    index: ?usize = null,
};

/// Where the first error happened: frames[0..depth] of the trace, the bit
/// position, and (for Incomplete) how many more input bits are needed.
pub const PbDiag = struct {
    failed: bool = false,
    bit_offset: usize = 0,
    needed_bits: usize = 0,
    depth: usize = 0,
};

/// The packets being decoded or encoded, innermost last, each with the field
/// it is working on: the path reported in errors.
pub const PbTrace = struct {
    frames: [PB_MAX_DEPTH]PbFrame = undefined,
    depth: usize = 0,
    diag: PbDiag = .{},

    fn fail(self: *PbTrace, err: PbError, pos: usize, needed_bits: usize) PbError {
        if (!self.diag.failed) {
            self.diag = .{ .failed = true, .bit_offset = pos, .needed_bits = needed_bits, .depth = self.depth };
        }
        return err;
    }

    fn enter(self: *PbTrace, packet: []const u8, pos: usize) PbError!void {
        if (self.depth >= PB_MAX_DEPTH) return self.fail(PbError.Invalid, pos, 0);
        self.frames[self.depth] = .{ .packet = packet };
        self.depth += 1;
    }

    fn leave(self: *PbTrace) void {
        if (self.depth > 0) self.depth -= 1;
    }

    fn at(self: *PbTrace, field: []const u8) void {
        self.frames[self.depth - 1].field = field;
        self.frames[self.depth - 1].index = null;
    }

    fn atIndex(self: *PbTrace, index: usize) void {
        self.frames[self.depth - 1].index = index;
    }

    /// Write `Packet.field[index].field` for the first error.
    pub fn writePath(self: *const PbTrace, w: anytype) !void {
        if (self.diag.depth == 0) return;
        try w.writeAll(self.frames[0].packet);
        for (self.frames[0..self.diag.depth]) |f| {
            if (f.field.len == 0) break;
            try w.print(".{s}", .{f.field});
            if (f.index) |i| try w.print("[{d}]", .{i});
        }
    }
};

/// Reads integers of any bit width (MSB-first) and byte-aligned values.
pub const PbReader = struct {
    data: []const u8,
    pos: usize = 0, // in bits
    limit: usize, // end of the readable data in bits (a window inside data)
    windows: usize = 0, // windows open
    trace: PbTrace = .{},

    pub fn init(data: []const u8) PbReader {
        return .{ .data = data, .limit = data.len * 8 };
    }

    pub fn remainingBits(self: *const PbReader) usize {
        return self.limit - self.pos;
    }

    pub fn positionBits(self: *const PbReader) usize {
        return self.pos;
    }

    pub fn fail(self: *PbReader, err: PbError) PbError {
        return self.trace.fail(err, self.pos, 0);
    }

    /// `bits` more bits are needed than are left: incomplete input at the
    /// top level, invalid data inside a window.
    fn short(self: *PbReader, bits: usize) PbError {
        if (self.windows == 0) {
            return self.trace.fail(PbError.Incomplete, self.pos, bits - self.remainingBits());
        }
        return self.trace.fail(PbError.Invalid, self.pos, 0);
    }

    fn need(self: *PbReader, bits: usize) PbError!void {
        if (bits > self.remainingBits()) return self.short(bits);
    }

    pub fn enter(self: *PbReader, packet: []const u8) PbError!void {
        return self.trace.enter(packet, self.pos);
    }

    pub fn leave(self: *PbReader) void {
        self.trace.leave();
    }

    pub fn at(self: *PbReader, field: []const u8) void {
        self.trace.at(field);
    }

    pub fn atIndex(self: *PbReader, index: usize) void {
        self.trace.atIndex(index);
    }

    /// Restrict reading to the next `n` bytes; returns the previous limit.
    pub fn pushLimit(self: *PbReader, n: i64) PbError!usize {
        if (n < 0) return self.fail(PbError.Invalid);
        const bytes: u64 = @intCast(n);
        if (bytes > self.remainingBits() / 8) return self.short(@intCast(@min(bytes * 8, std.math.maxInt(usize))));
        const saved = self.limit;
        self.limit = self.pos + @as(usize, @intCast(bytes)) * 8;
        self.windows += 1;
        return saved;
    }

    /// Skip what is left of the current window and restore `saved`; with
    /// `exact`, bytes left over are an error.
    pub fn popLimit(self: *PbReader, saved: usize, exact: bool) PbError!void {
        if (exact and self.remainingBits() > 0) return self.fail(PbError.Invalid);
        self.pos = self.limit;
        self.limit = saved;
        self.windows -= 1;
    }

    pub fn readBits(self: *PbReader, width: u7) PbError!u64 {
        try self.need(width);
        var v: u64 = 0;
        var left: u7 = width;
        while (left > 0) {
            const off: u4 = @intCast(self.pos & 7);
            const take: u4 = @intCast(@min(@as(u7, 8 - off), left));
            const byte: u8 = self.data[self.pos >> 3];
            const bits: u8 = (byte >> @intCast(8 - off - take)) & @as(u8, @intCast((@as(u9, 1) << take) - 1));
            v = (v << @intCast(take)) | bits;
            self.pos += take;
            left -= take;
        }
        return v;
    }

    pub fn readUint(self: *PbReader, nbytes: u4, little: bool) PbError!u64 {
        try self.need(@as(usize, nbytes) * 8);
        const start = self.pos >> 3;
        var v: u64 = 0;
        var i: usize = 0;
        while (i < nbytes) : (i += 1) {
            const b = if (little) self.data[start + nbytes - 1 - i] else self.data[start + i];
            v = (v << 8) | b;
        }
        self.pos += @as(usize, nbytes) * 8;
        return v;
    }

    /// Copy `n` bytes into a new allocation owned by the caller.
    pub fn readBytes(self: *PbReader, allocator: std.mem.Allocator, n: usize) PbError![]u8 {
        if (n > self.remainingBits() / 8) return self.short(n * 8);
        const start = self.pos >> 3;
        const out = try allocator.dupe(u8, self.data[start .. start + n]);
        self.pos += n * 8;
        return out;
    }

    pub fn readMac(self: *PbReader) PbError![6]u8 {
        try self.need(48);
        const start = self.pos >> 3;
        self.pos += 48;
        return self.data[start..][0..6].*;
    }

    pub fn skipBits(self: *PbReader, bits: usize) PbError!void {
        try self.need(bits);
        self.pos += bits;
    }

    /// `n` bytes of UTF-8 text, cut at the first NUL when `until_nul` is set.
    pub fn readText(self: *PbReader, allocator: std.mem.Allocator, n: usize, until_nul: bool) PbError![]u8 {
        if (n > self.remainingBits() / 8) return self.short(n * 8);
        const start = self.pos >> 3;
        var raw = self.data[start .. start + n];
        if (until_nul) {
            if (std.mem.indexOfScalar(u8, raw, 0)) |end| raw = raw[0..end];
        }
        if (!std.unicode.utf8ValidateSlice(raw)) return self.fail(PbError.InvalidText);
        const out = try allocator.dupe(u8, raw);
        self.pos += n * 8;
        return out;
    }

    /// UTF-8 text before a NUL terminator; the terminator is consumed.
    pub fn readCText(self: *PbReader, allocator: std.mem.Allocator) PbError![]u8 {
        const start = self.pos >> 3;
        const window = self.data[0 .. self.limit >> 3];
        const end = std.mem.indexOfScalarPos(u8, window, start, 0) orelse return self.short(self.remainingBits() + 8);
        const raw = self.data[start..end];
        if (!std.unicode.utf8ValidateSlice(raw)) return self.fail(PbError.InvalidText);
        const out = try allocator.dupe(u8, raw);
        self.pos = (end + 1) * 8;
        return out;
    }

    /// Checksum `algo` of the input between two bit positions (whole bytes);
    /// the bytes between `hole_from` and `hole_to` count as zero.
    pub fn checksum(self: *const PbReader, algo: u32, from: usize, to: usize, hole_from: usize, hole_to: usize) u64 {
        return pbChecksum(algo, self.data, from / 8, to / 8, hole_from / 8, hole_to / 8);
    }

    /// Validate a decoded element count against the data that is left.
    pub fn count(self: *PbReader, n: i64, elem_bits: u64) PbError!usize {
        if (n < 0) return self.fail(PbError.Invalid);
        const un: u64 = @intCast(n);
        if (elem_bits > 0 and un > self.remainingBits() / elem_bits) {
            const bits = std.math.mul(u64, un, elem_bits) catch std.math.maxInt(u64);
            return self.short(@intCast(@min(bits, std.math.maxInt(usize))));
        }
        return @intCast(n);
    }
};

/// Builds a byte buffer; integers may be written at any bit position.
pub const PbWriter = struct {
    buf: std.ArrayList(u8),
    pos: usize = 0, // in bits
    trace: PbTrace = .{},

    pub fn init(allocator: std.mem.Allocator) PbWriter {
        return .{ .buf = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *PbWriter) void {
        self.buf.deinit();
    }

    pub fn toOwnedSlice(self: *PbWriter) PbError![]u8 {
        return self.buf.toOwnedSlice();
    }

    pub fn positionBits(self: *const PbWriter) usize {
        return self.pos;
    }

    pub fn fail(self: *PbWriter, err: PbError) PbError {
        return self.trace.fail(err, self.pos, 0);
    }

    pub fn enter(self: *PbWriter, packet: []const u8) PbError!void {
        return self.trace.enter(packet, self.pos);
    }

    pub fn leave(self: *PbWriter) void {
        self.trace.leave();
    }

    pub fn at(self: *PbWriter, field: []const u8) void {
        self.trace.at(field);
    }

    pub fn atIndex(self: *PbWriter, index: usize) void {
        self.trace.atIndex(index);
    }

    pub fn writeBits(self: *PbWriter, value: u64, width: u7) PbError!void {
        var left: u7 = width;
        while (left > 0) {
            if (self.pos & 7 == 0) try self.buf.append(0);
            const off: u4 = @intCast(self.pos & 7);
            const take: u4 = @intCast(@min(@as(u7, 8 - off), left));
            const bits: u8 = @intCast((value >> @intCast(left - take)) & ((@as(u64, 1) << take) - 1));
            self.buf.items[self.buf.items.len - 1] |= bits << @intCast(8 - off - take);
            self.pos += take;
            left -= take;
        }
    }

    pub fn writeUint(self: *PbWriter, value: u64, nbytes: u4, little: bool) PbError!void {
        var i: u6 = 0;
        while (i < nbytes) : (i += 1) {
            const shift: u6 = if (little) 8 * i else 8 * (@as(u6, nbytes) - 1 - i);
            try self.buf.append(@truncate(value >> shift));
        }
        self.pos += @as(usize, nbytes) * 8;
    }

    pub fn writeBytes(self: *PbWriter, bytes: []const u8) PbError!void {
        try self.buf.appendSlice(bytes);
        self.pos += bytes.len * 8;
    }

    pub fn writeZeroBits(self: *PbWriter, bits: i64) PbError!void {
        var left = bits;
        while (left > 32) : (left -= 32) try self.writeBits(0, 32);
        if (left > 0) try self.writeBits(0, @intCast(left));
    }

    pub fn checkText(self: *PbWriter, s: []const u8, allow_nul: bool) PbError!void {
        if (!allow_nul and std.mem.indexOfScalar(u8, s, 0) != null) return self.fail(PbError.InvalidText);
        if (!std.unicode.utf8ValidateSlice(s)) return self.fail(PbError.InvalidText);
    }

    pub fn checkFits(self: *PbWriter, len: usize, size: i64) PbError!void {
        if (size < 0 or len > @as(u64, @intCast(size))) return self.fail(PbError.Range);
    }

    pub fn checkPrefix(self: *PbWriter, len: usize, width: u7) PbError!void {
        if (width < 64 and (len >> @intCast(width)) != 0) return self.fail(PbError.Range);
    }

    /// End a window of `size` bytes that started at bit `start`: the content
    /// must fit (and fill it when `exact`); the rest is zero-filled.
    pub fn endWindow(self: *PbWriter, start: usize, size: i64, exact: bool) PbError!void {
        const used: i64 = @intCast(self.pos - start);
        if (size < 0 or used > size * 8) return self.fail(PbError.Range);
        if (exact and used != size * 8) return self.fail(PbError.Mismatch);
        try self.writeZeroBits(size * 8 - used);
    }

    /// Overwrite `nbytes` bytes at bit position `pos` (byte aligned).
    pub fn patchUint(self: *PbWriter, pos: usize, value: u64, nbytes: u4, little: bool) void {
        var i: u6 = 0;
        while (i < nbytes) : (i += 1) {
            const shift: u6 = if (little) 8 * i else 8 * (@as(u6, nbytes) - 1 - i);
            self.buf.items[pos / 8 + i] = @truncate(value >> shift);
        }
    }

    /// Overwrite `width` bits at bit position `pos`, MSB first.
    pub fn patchBits(self: *PbWriter, pos: usize, value: u64, width: u7) void {
        var i: usize = 0;
        while (i < width) : (i += 1) {
            const bit: u8 = @intCast((value >> @intCast(width - 1 - i)) & 1);
            const off: u3 = @intCast(7 - (pos + i) % 8);
            const byte = &self.buf.items[(pos + i) / 8];
            byte.* = (byte.* & ~(@as(u8, 1) << off)) | (bit << off);
        }
    }

    /// Checksum `algo` of the output between two bit positions (whole
    /// bytes); the bytes between `hole_from` and `hole_to` count as zero.
    pub fn checksum(self: *const PbWriter, algo: u32, from: usize, to: usize, hole_from: usize, hole_to: usize) u64 {
        return pbChecksum(algo, self.buf.items, from / 8, to / 8, hole_from / 8, hole_to / 8);
    }

    /// A computed value must fit an unsigned field of `width` bits (any bit
    /// pattern fits 64 bits).
    pub fn checkU(self: *PbWriter, v: i64, width: u7) PbError!void {
        if (width < 64 and (v < 0 or (@as(u64, @intCast(v)) >> @intCast(width)) != 0)) return self.fail(PbError.Range);
    }

    /// A computed value must fit a signed field of `width` bits.
    pub fn checkI(self: *PbWriter, v: i64, width: u7) PbError!void {
        if (width >= 64) return;
        const half = @as(i64, 1) << @intCast(width - 1);
        if (v < -half or v >= half) return self.fail(PbError.Range);
    }

    pub fn checkLen(self: *PbWriter, actual: usize, expected: i64) PbError!void {
        if (expected < 0 or actual != @as(u64, @intCast(expected))) return self.fail(PbError.Mismatch);
    }
};

const PbCrc = struct { width: u6, poly: u64, init: u64, reflected: bool, xorout: u64 };

/// CRC parameters by algorithm number (polynomials of reflected CRCs are
/// reflected).
const pb_crc = [8]PbCrc{
    .{ .width = 8, .poly = 0x07, .init = 0, .reflected = false, .xorout = 0 }, // crc8 (CRC-8/SMBUS)
    .{ .width = 16, .poly = 0xa001, .init = 0, .reflected = true, .xorout = 0 }, // crc16_arc
    .{ .width = 16, .poly = 0x1021, .init = 0xffff, .reflected = false, .xorout = 0 }, // crc16_ccitt_false
    .{ .width = 16, .poly = 0x1021, .init = 0, .reflected = false, .xorout = 0 }, // crc16_xmodem
    .{ .width = 16, .poly = 0x8408, .init = 0, .reflected = true, .xorout = 0 }, // crc16_kermit
    .{ .width = 16, .poly = 0xa001, .init = 0xffff, .reflected = true, .xorout = 0 }, // crc16_modbus
    .{ .width = 32, .poly = 0xedb88320, .init = 0xffffffff, .reflected = true, .xorout = 0xffffffff }, // crc32
    .{ .width = 32, .poly = 0x82f63b78, .init = 0xffffffff, .reflected = true, .xorout = 0xffffffff }, // crc32c
};

/// Checksum `algo` of buf[from..to] with buf[hole_from..hole_to] as zeros.
/// 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8.
fn pbChecksum(algo: u32, buf: []const u8, from: usize, to: usize, hole_from: usize, hole_to: usize) u64 {
    if (algo < 8) {
        const p = pb_crc[algo];
        const mask: u64 = (@as(u64, 1) << p.width) - 1;
        var crc = p.init;
        var i = from;
        while (i < to) : (i += 1) {
            const x: u64 = if (i >= hole_from and i < hole_to) 0 else buf[i];
            var k: u4 = 0;
            if (p.reflected) {
                crc ^= x;
                while (k < 8) : (k += 1) crc = if (crc & 1 != 0) (crc >> 1) ^ p.poly else crc >> 1;
            } else {
                crc ^= x << (p.width - 8);
                while (k < 8) : (k += 1) {
                    crc = (if (crc & (@as(u64, 1) << (p.width - 1)) != 0) (crc << 1) ^ p.poly else crc << 1) & mask;
                }
            }
        }
        return (crc ^ p.xorout) & mask;
    }
    var a: u64 = 0;
    var b: u64 = 0;
    var i = from;
    while (i < to) : (i += 1) {
        const x: u64 = if (i >= hole_from and i < hole_to) 0 else buf[i];
        switch (algo) {
            8 => a += if ((i - from) % 2 == 0) x << 8 else x,
            9 => {
                a = (a + x) % 255;
                b = (b + a) % 255;
            },
            10 => a = (a + x) & 0xff,
            else => a ^= x,
        }
    }
    if (algo == 8) {
        while (a >> 16 != 0) a = (a & 0xffff) + (a >> 16);
        return ~a & 0xffff;
    }
    if (algo == 9) return (b << 8) | a;
    return a;
}

/// Padding needed after `offset` bits to reach a multiple of `unit` bits.
fn pbPad(offset: usize, unit: usize) usize {
    return (unit - offset % unit) % unit;
}

/// Reinterpret the low bits of a raw value as `T` (sign comes from `T`).
fn pbFromBits(comptime T: type, raw: u64) T {
    const U = std.meta.Int(.unsigned, @bitSizeOf(T));
    const bits: U = @truncate(raw);
    return @bitCast(bits);
}

/// Two's complement bits of an integer, zero-extended to 64 bits.
fn pbToBits(v: anytype) u64 {
    const U = std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(v)));
    return @as(U, @bitCast(v));
}

/// Wrap an i64 to `T`.
fn pbStore(comptime T: type, v: i64) T {
    return pbFromBits(T, @bitCast(v));
}

fn pbI64(v: anytype) i64 {
    const T = @TypeOf(v);
    if (T == f32 or T == f64) return pbFtoI(v);
    if (@bitSizeOf(T) == 64 and std.math.minInt(T) == 0) return @bitCast(v);
    return @intCast(v);
}

fn pbF64(v: anytype) f64 {
    const T = @TypeOf(v);
    if (T == f32 or T == f64) return @floatCast(v);
    return @floatFromInt(v);
}

fn pbFtoI(v: f64) i64 {
    if (std.math.isNan(v)) return 0;
    if (v >= 9223372036854775807.0) return std.math.maxInt(i64);
    if (v <= -9223372036854775808.0) return std.math.minInt(i64);
    return @intFromFloat(v);
}

fn pbDiv(a: i64, b: i64) i64 {
    if (b == 0) return 0;
    if (b == -1) return 0 -% a;
    return @divTrunc(a, b);
}

fn pbMod(a: i64, b: i64) i64 {
    if (b == 0 or b == -1) return 0;
    return @rem(a, b);
}

fn pbShl(a: i64, b: i64) i64 {
    if (b < 0 or b > 63) return 0;
    return a << @intCast(b);
}

fn pbShr(a: i64, b: i64) i64 {
    if (b < 0) return 0;
    return a >> @intCast(@min(b, 63));
}

fn pbPow(base: i64, exp: i64) i64 {
    if (exp < 0) return 0;
    var acc: i64 = 1;
    var b = base;
    var e: u64 = @intCast(exp);
    while (e > 0) : (e >>= 1) {
        if (e & 1 == 1) acc *%= b;
        b *%= b;
    }
    return acc;
}

fn pbAt(s: anytype, i: i64) std.meta.Elem(@TypeOf(s)) {
    if (i < 0 or i >= s.len) return std.mem.zeroes(std.meta.Elem(@TypeOf(s)));
    return s[@intCast(i)];
}

fn pbSum(s: anytype) i64 {
    var acc: i64 = 0;
    for (s) |v| acc +%= pbI64(v);
    return acc;
}

fn pbProd(s: anytype) i64 {
    var acc: i64 = 1;
    for (s) |v| acc *%= pbI64(v);
    return acc;
}

fn pbSumF(s: anytype) f64 {
    var acc: f64 = 0;
    for (s) |v| acc += pbF64(v);
    return acc;
}

fn pbProdF(s: anytype) f64 {
    var acc: f64 = 1;
    for (s) |v| acc *= pbF64(v);
    return acc;
}

// ---- generated packets ------------------------------------------------------
