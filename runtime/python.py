# ---- packet-builder runtime -------------------------------------------------


class PbError(Exception):
    """Raised when data cannot be decoded or a value cannot be encoded."""


class PbReader:
    """Reads integers of any bit width (MSB-first) and byte-aligned values."""

    __slots__ = ("data", "pos")

    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0  # in bits

    def remaining_bits(self):
        return len(self.data) * 8 - self.pos

    def position_bits(self):
        return self.pos

    def _need(self, bits):
        if bits > self.remaining_bits():
            raise PbError(
                "unexpected end of data: need %d more bit(s) at bit offset %d, have %d"
                % (bits, self.pos, self.remaining_bits())
            )

    def read_bits(self, width):
        self._need(width)
        v = 0
        left = width
        while left > 0:
            byte = self.data[self.pos >> 3]
            off = self.pos & 7
            take = min(8 - off, left)
            v = (v << take) | ((byte >> (8 - off - take)) & ((1 << take) - 1))
            self.pos += take
            left -= take
        return v

    def read_uint(self, nbytes, little):
        self._need(nbytes * 8)
        start = self.pos >> 3
        self.pos += nbytes * 8
        return int.from_bytes(self.data[start:start + nbytes], "little" if little else "big")

    def read_bytes(self, n):
        self._need(n * 8)
        start = self.pos >> 3
        self.pos += n * 8
        return self.data[start:start + n]

    def skip_bits(self, bits):
        self._need(bits)
        self.pos += bits

    def read_cstring(self, field):
        start = self.pos >> 3
        end = self.data.find(b"\0", start)
        if end < 0:
            raise PbError("unexpected end of data: string `%s` has no NUL terminator" % field)
        self.pos = (end + 1) * 8
        return self.data[start:end]


class PbWriter:
    """Builds a byte buffer; integers may be written at any bit position."""

    __slots__ = ("buf", "pos")

    def __init__(self):
        self.buf = bytearray()
        self.pos = 0  # in bits

    def position_bits(self):
        return self.pos

    def write_bits(self, value, width):
        left = width
        while left > 0:
            if self.pos & 7 == 0:
                self.buf.append(0)
            off = self.pos & 7
            take = min(8 - off, left)
            bits = (value >> (left - take)) & ((1 << take) - 1)
            self.buf[-1] |= bits << (8 - off - take)
            self.pos += take
            left -= take

    def write_uint(self, value, nbytes, little):
        self.buf += (value & ((1 << (8 * nbytes)) - 1)).to_bytes(nbytes, "little" if little else "big")
        self.pos += nbytes * 8

    def write_bytes(self, data):
        self.buf += data
        self.pos += len(data) * 8

    def write_zero_bits(self, bits):
        while bits > 0:
            take = min(bits, 32)
            self.write_bits(0, take)
            bits -= take

    def finish(self):
        return bytes(self.buf)


def _pb_pad(offset, unit):
    """Padding needed after `offset` bits to reach a multiple of `unit` bits."""
    return (unit - offset % unit) % unit


def _pb_utf8(raw, field):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PbError("invalid UTF-8 in string field `%s`" % field) from None


def _pb_utf8_bytes(text, field):
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise PbError("string field `%s` is not valid Unicode" % field) from None


def _pb_until_nul(raw):
    end = raw.find(b"\0")
    return raw if end < 0 else raw[:end]


def _pb_check_fits(length, size, field):
    if length > size:
        raise PbError("string field `%s` is %d byte(s), longer than its size %d" % (field, length, size))


def _pb_check_no_nul(data, field):
    if b"\0" in data:
        raise PbError("string field `%s` contains a NUL byte" % field)


def _pb_wrap(v):
    """Wrap to a signed 64-bit integer."""
    return ((v + (1 << 63)) & ((1 << 64) - 1)) - (1 << 63)


def _pb_sext(v, width):
    if (v >> (width - 1)) & 1:
        return v - (1 << width)
    return v


def _pb_trunc(v, width, signed):
    v &= (1 << width) - 1
    return _pb_sext(v, width) if signed else v


def _pb_div(a, b):
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return _pb_wrap(q if (a < 0) == (b < 0) else -q)


def _pb_pow(a, b):
    if b < 0:
        return 0
    return _pb_wrap(pow(a, b, 1 << 64))


def _pb_fdiv(a, b):
    if b == 0.0:
        if a == 0.0 or a != a:
            return float("nan")
        return math.copysign(float("inf"), a) * math.copysign(1.0, b)
    return a / b


def _pb_fpow(a, b):
    try:
        return math.pow(a, b)
    except (OverflowError, ValueError):
        return float("nan")


def _pb_sqrt(a):
    return math.sqrt(a) if a >= 0 else float("nan")


def _pb_ftoi(v):
    if v != v:
        return 0
    if v >= 9.223372036854775807e18:
        return (1 << 63) - 1
    if v <= -9.223372036854775808e18:
        return -(1 << 63)
    return int(v)


def _pb_f32(v):
    return struct.unpack("<f", struct.pack("<f", v))[0]


def _pb_at(seq, i):
    return seq[i] if 0 <= i < len(seq) else 0


def _pb_count(n, elem_bits, r, field):
    if n < 0:
        raise PbError("negative length %d for field `%s`" % (n, field))
    if elem_bits > 0 and n > r.remaining_bits() // elem_bits:
        raise PbError("length %d for field `%s` exceeds the remaining data" % (n, field))
    return n


def _pb_check_len(actual, expected, field):
    if actual != expected:
        raise PbError(
            "field `%s` has %d element(s) but its length expression says %d" % (field, actual, expected)
        )


def _pb_check_u(v, width, field):
    if v < 0 or v >> width:
        raise PbError("value %d does not fit in %d bit(s) for field `%s`" % (v, width, field))


def _pb_check_i(v, width, field):
    if v < -(1 << (width - 1)) or v >= (1 << (width - 1)):
        raise PbError("value %d does not fit in %d signed bit(s) for field `%s`" % (v, width, field))


# ---- generated packets ------------------------------------------------------
