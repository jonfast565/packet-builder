# ---- packet-builder runtime -------------------------------------------------


class PbError(Exception):
    """Raised when data cannot be decoded or a value cannot be encoded.

    `kind` is one of the PbError.* kinds, `path` says where it happened
    (`Packet.field[index].field`), `bit_offset` is the reader or writer
    position, and `needed_bits` (for INCOMPLETE) is the least number of extra
    input bits needed.
    """

    INCOMPLETE = "incomplete"  # the input ended before the packet did
    INVALID = "invalid"  # malformed data: a bad length, nesting too deep, ...
    RANGE = "range"  # a value does not fit in its field
    TEXT = "text"  # a string is not valid text, or contains a NUL where none is allowed
    MISMATCH = "mismatch"  # a length, derived field or checksum does not match the data
    CONSTRAINT = "constraint"  # a value breaks a declared constraint

    def __init__(self, kind, message, path="", bit_offset=0, needed_bits=0):
        self.kind = kind
        self.message = message
        self.path = path
        self.bit_offset = bit_offset
        self.needed_bits = needed_bits
        where = "%s: " % path if path else ""
        super().__init__("%s%s (at bit %d)" % (where, message, bit_offset))


PB_MAX_DEPTH = 64  # deepest packet nesting accepted


class _PbTrace:
    """The packets being decoded or encoded, innermost last, each with the
    field it is working on: the path reported in errors."""

    __slots__ = ("frames", "pos")

    def __init__(self):
        self.frames = []  # [packet, field, index]
        self.pos = 0  # in bits

    def enter(self, packet):
        self.frames.append([packet, "", None])
        if len(self.frames) > PB_MAX_DEPTH:
            raise self.error(PbError.INVALID, "packets nested more than %d deep" % PB_MAX_DEPTH)

    def leave(self):
        self.frames.pop()

    def at(self, field):
        frame = self.frames[-1]
        frame[1] = field
        frame[2] = None

    def at_index(self, index):
        self.frames[-1][2] = index

    def path(self):
        parts = [self.frames[0][0]] if self.frames else []
        for _, field, index in self.frames:
            if not field:
                break
            parts.append(field if index is None else "%s[%d]" % (field, index))
        return ".".join(parts)

    def error(self, kind, message):
        return PbError(kind, message, self.path(), self.pos)


class PbReader(_PbTrace):
    """Reads integers of any bit width (MSB-first) and byte-aligned values."""

    __slots__ = ("data", "limit")

    def __init__(self, data):
        super().__init__()
        self.data = bytes(data)
        self.limit = len(self.data) * 8  # end of the readable data (a window inside data)

    def remaining_bits(self):
        return self.limit - self.pos

    def position_bits(self):
        return self.pos

    def _short(self, bits, what):
        """`bits` more bits are needed than are left."""
        left = self.remaining_bits()
        if self.limit == len(self.data) * 8:
            e = self.error(
                PbError.INCOMPLETE,
                "unexpected end of data: %s needs %d more bit(s), %d left" % (what, bits, left),
            )
            e.needed_bits = bits - left
            return e
        return self.error(PbError.INVALID, "%s needs %d bit(s) but its window has %d left" % (what, bits, left))

    def _need(self, bits):
        if bits > self.remaining_bits():
            raise self._short(bits, "the field")

    def push_limit(self, nbytes):
        """Restrict reading to the next `nbytes` bytes; returns the previous limit."""
        if nbytes < 0:
            raise self.error(PbError.INVALID, "negative size %d" % nbytes)
        if nbytes * 8 > self.remaining_bits():
            raise self._short(nbytes * 8, "the window")
        saved = self.limit
        self.limit = self.pos + nbytes * 8
        return saved

    def pop_limit(self, saved):
        """Skip what is left of the current window and restore `saved`."""
        self.pos = self.limit
        self.limit = saved

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

    def read_cstring(self):
        start = self.pos >> 3
        end = self.data.find(b"\0", start, self.limit >> 3)
        if end < 0:
            raise self._short(self.remaining_bits() + 8, "the NUL-terminated string")
        self.pos = (end + 1) * 8
        return self.data[start:end]

    def count(self, n, elem_bits):
        """Validate a decoded element count against the data that is left."""
        if n < 0:
            raise self.error(PbError.INVALID, "negative length %d" % n)
        if elem_bits > 0 and n > self.remaining_bits() // elem_bits:
            raise self._short(n * elem_bits, "length %d" % n)
        return n

    def utf8(self, raw):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise self.error(PbError.TEXT, "invalid UTF-8") from None


class PbWriter(_PbTrace):
    """Builds a byte buffer; integers may be written at any bit position."""

    __slots__ = ("buf",)

    def __init__(self):
        super().__init__()
        self.buf = bytearray()

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

    def utf8_bytes(self, text):
        try:
            return text.encode("utf-8")
        except UnicodeEncodeError:
            raise self.error(PbError.TEXT, "the string is not valid Unicode") from None

    def check_fits(self, length, size):
        if length > size:
            raise self.error(PbError.RANGE, "%d byte(s) do not fit in %d" % (length, size))

    def check_no_nul(self, data):
        if b"\0" in data:
            raise self.error(PbError.TEXT, "the string contains a NUL byte")

    def check_len(self, actual, expected):
        if actual != expected:
            raise self.error(
                PbError.MISMATCH, "%d element(s) but the length expression says %d" % (actual, expected)
            )

    def check_u(self, v, width):
        if v < 0 or v >> width:
            raise self.error(PbError.RANGE, "value %d does not fit in %d bit(s)" % (v, width))

    def check_i(self, v, width):
        if not -(1 << (width - 1)) <= v < (1 << (width - 1)):
            raise self.error(PbError.RANGE, "value %d does not fit in %d signed bit(s)" % (v, width))


def _pb_pad(offset, unit):
    """Padding needed after `offset` bits to reach a multiple of `unit` bits."""
    return (unit - offset % unit) % unit


def _pb_until_nul(raw):
    end = raw.find(b"\0")
    return raw if end < 0 else raw[:end]


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


def _pb_mod(a, b):
    if b == 0:
        return 0
    r = abs(a) % abs(b)
    return -r if a < 0 else r


def _pb_shl(a, b):
    if b < 0 or b > 63:
        return 0
    return _pb_wrap(a << b)


def _pb_shr(a, b):
    if b < 0:
        return 0
    return a >> min(b, 63)


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


# ---- generated packets ------------------------------------------------------
