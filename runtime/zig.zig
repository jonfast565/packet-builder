// ---- packet-builder runtime -------------------------------------------------

pub const PbError = error{ EndOfData, InvalidLength, OutOfMemory };

/// Reads integers of any bit width (MSB-first) and byte-aligned values.
pub const PbReader = struct {
    data: []const u8,
    pos: usize = 0, // in bits

    pub fn init(data: []const u8) PbReader {
        return .{ .data = data };
    }

    pub fn remainingBits(self: *const PbReader) usize {
        return self.data.len * 8 - self.pos;
    }

    fn need(self: *const PbReader, bits: usize) PbError!void {
        if (bits > self.remainingBits()) return PbError.EndOfData;
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
        if (n > self.remainingBits() / 8) return PbError.EndOfData;
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

    /// Validate a decoded element count against the data that is left.
    pub fn count(self: *const PbReader, n: i64, elem_bits: u64) PbError!usize {
        if (n < 0) return PbError.InvalidLength;
        if (elem_bits > 0 and @as(u64, @intCast(n)) > self.remainingBits() / elem_bits) return PbError.InvalidLength;
        return @intCast(n);
    }
};

/// Builds a byte buffer; integers may be written at any bit position.
pub const PbWriter = struct {
    buf: std.ArrayList(u8),
    pos: usize = 0, // in bits

    pub fn init(allocator: std.mem.Allocator) PbWriter {
        return .{ .buf = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *PbWriter) void {
        self.buf.deinit();
    }

    pub fn toOwnedSlice(self: *PbWriter) PbError![]u8 {
        return self.buf.toOwnedSlice();
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
};

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

fn pbCheckLen(actual: usize, expected: i64) PbError!void {
    if (expected < 0 or actual != @as(u64, @intCast(expected))) return PbError.InvalidLength;
}

// ---- generated packets ------------------------------------------------------
