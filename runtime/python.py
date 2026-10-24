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

    __slots__ = ("frames", "pos", "version")

    def __init__(self):
        self.frames = []  # [packet, field, index]
        self.pos = 0  # in bits
        self.version = 0  # protocol version; 0 until set

    # @versions{
    def version_or(self, latest):
        """The protocol version (`version`), or `latest` while none is set."""
        return self.version or latest

    def set_version(self, v, lo, latest):
        """Code as protocol version `v`, which must be in `lo..latest`."""
        if not lo <= v <= latest:
            raise self.error(PbError.CONSTRAINT, "version %d is not one of the versions %d..%d" % (v, lo, latest))
        self.version = v

    def adopt_version(self, v, lo, latest):
        """The version a value carries in-band: used unless one is set already."""
        if not self.version:
            self.set_version(v, lo, latest)
    # @versions}

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

    __slots__ = ("data", "limit", "windows")

    def __init__(self, data):
        super().__init__()
        self.data = data if isinstance(data, bytes) else bytes(data)
        self.limit = len(self.data) * 8  # end of the readable data (a window inside data)
        self.windows = 0  # windows open

    def remaining_bits(self):
        return self.limit - self.pos

    def remaining_bytes(self):
        """Whole bytes left before the end of the window or input (`remaining`)."""
        return (self.limit - self.pos) // 8

    def jump(self, start, offset):
        """Read from `offset` bytes after bit `start` (the packet start, or 0
        for the start of the input) until `jump_back`; windows do not apply."""
        target = start + offset * 8
        if offset < 0 or start % 8 or target > len(self.data) * 8:
            raise self.error(PbError.INVALID, "offset %d is past the end of the input" % offset)
        saved = (self.pos, self.limit, self.windows)
        self.pos, self.limit, self.windows = target, len(self.data) * 8, 0
        return saved

    def jump_back(self, saved):
        self.pos, self.limit, self.windows = saved

    def position_bits(self):
        return self.pos

    def _short(self, bits, what):
        """`bits` more bits are needed than are left."""
        left = self.remaining_bits()
        if self.windows == 0:
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
        self.windows += 1
        return saved

    def pop_limit(self, saved, exact):
        """Skip what is left of the current window and restore `saved`; with
        `exact`, bytes left over are an error."""
        if exact and self.remaining_bits() > 0:
            raise self.error(
                PbError.INVALID, "%d bit(s) left over in a field that must fill its size" % self.remaining_bits()
            )
        self.pos = self.limit
        self.limit = saved
        self.windows -= 1

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

    def text(self, raw, enc, padded):
        """Text in encoding `enc` (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
        4 UTF-16BE); `padded` cuts it at the first NUL character."""
        if enc >= 3:
            if len(raw) % 2:
                raise self.error(PbError.TEXT, "invalid UTF-16 (an odd number of bytes)")
            if padded:
                for i in range(0, len(raw), 2):
                    if raw[i] == 0 and raw[i + 1] == 0:
                        raw = raw[:i]
                        break
        elif padded:
            raw = _pb_until_nul(raw)
        name = _PB_ENCODINGS[enc]
        try:
            return bytes(raw).decode(name)
        except UnicodeDecodeError:
            raise self.error(PbError.TEXT, "invalid %s" % name) from None

    def read_varint(self, kind):
        """One variable-length integer (`kind`: 0 uleb128, 1 sleb128,
        2 zigzag, 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits."""
        if kind == 5:
            first = self.read_uint(1, False)
            if first & 0x80 == 0:
                return first
            return ((first & 0x7F) << 8) | self.read_uint(1, False)
        if kind == 4:
            first = self.read_uint(1, False)
            n = 1 << (first >> 6)
            v = first & 0x3F
            if n > 1:
                v = (v << (8 * (n - 1))) | self.read_uint(n - 1, False)
            return v
        v = 0
        shift = 0
        while True:
            b = self.read_uint(1, False)
            if kind == 3:
                if v >> 57:
                    raise self.error(PbError.INVALID, "the varint does not fit in 64 bits")
                v = (v << 7) | (b & 0x7F)
            else:
                # The 10th byte holds bit 63 only (and, for sleb128, its sign).
                last_ok = (b & 0x7F) in (0, 0x7F) if kind == 1 else (b & 0x7E) == 0
                if shift >= 64 or (shift == 63 and (b & 0x80 or not last_ok)):
                    raise self.error(PbError.INVALID, "the varint does not fit in 64 bits")
                v |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                if kind == 1 and shift < 64 and b & 0x40:
                    v |= ((1 << 64) - 1) << shift
                break
        v &= (1 << 64) - 1
        if kind == 2:
            v = (v >> 1) ^ (-(v & 1) & ((1 << 64) - 1))
        return v

    def read_view(self, n):
        """The next n bytes as a memoryview of the input (zero-copy)."""
        self._need(n * 8)
        start = self.pos >> 3
        self.pos += n * 8
        return memoryview(self.data)[start:start + n]

    def read_until_view(self, term, optional):
        """read_until as a memoryview of the input (zero-copy)."""
        start = self.pos >> 3
        n = len(self.read_until(term, optional))
        return memoryview(self.data)[start:start + n]

    def read_until(self, term, optional):
        """The bytes before `term`, consuming both. Without the terminator: the
        rest of the input when `optional`, otherwise an error."""
        start = self.pos >> 3
        end = self.data.find(term, start, self.limit >> 3)
        if end < 0:
            if not optional:
                raise self._short(self.remaining_bits() + 8, "the terminated field")
            self.pos = self.limit
            return self.data[start:self.limit >> 3]
        self.pos = (end + len(term)) * 8
        return self.data[start:end]

    def checksum(self, algo, start, end, hole_start, hole_end):
        """Checksum `algo` of the input between two bit positions (whole
        bytes); the bytes between `hole_start` and `hole_end` count as zero."""
        return _pb_checksum(algo, self.data, start // 8, end // 8, hole_start // 8, hole_end // 8)


class PbWriter(_PbTrace):
    """Builds a byte buffer; integers may be written at any bit position."""

    __slots__ = ("buf", "base", "placed")

    def __init__(self):
        super().__init__()
        self.buf = bytearray()
        self.base = 0  # where buf goes in the output, in bits (sub writers)
        self.placed = []  # (byte offset, bytes, path) of packets placed with `at`

    def sub(self, start, offset, root):
        """A writer for a packet placed `offset` bytes after bit `start` of this
        writer (the packet start), or after the start of the output (`root`)."""
        start = 0 if root else self.base + start
        if offset < 0 or start % 8:
            raise self.error(PbError.RANGE, "bad offset %d (from bit %d)" % (offset, start))
        s = PbWriter()
        s.version = self.version
        s.base = start + offset * 8
        s.frames = [list(f) for f in self.frames]
        return s

    def place(self, s):
        """Keep what `s` wrote, for `finish`."""
        self.placed.append((s.base // 8, bytes(s.buf), self.path()))
        self.placed.extend(s.placed)

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
        """The output, with every placed packet written at its offset: past the
        end (zero-filling the gap), or over bytes that must already match."""
        for at, data, path in sorted(self.placed, key=lambda p: p[0]):
            # The output reaches the offset even when the packet is empty.
            if len(self.buf) < at:
                self.buf += bytes(at - len(self.buf))
            for i, b in enumerate(data):
                k = at + i
                if k < len(self.buf):
                    if self.buf[k] != b:
                        msg = "the packet placed at byte %d does not match the bytes already there" % at
                        raise PbError(PbError.MISMATCH, msg, path, k * 8)
                else:
                    self.buf += bytes(k - len(self.buf))
                    self.buf.append(b)
        self.placed = []
        return bytes(self.buf)

    def end_window(self, start, size, exact):
        """End a window of `size` bytes that started at bit `start`: the
        content must fit (and fill it when `exact`); the rest is zero-filled."""
        used = self.pos - start
        if size < 0 or used > size * 8:
            raise self.error(
                PbError.RANGE, "the content takes %d bit(s), more than its size of %d byte(s)" % (used, size)
            )
        if exact and used != size * 8:
            raise self.error(
                PbError.MISMATCH, "the content takes %d bit(s) but must fill its %d byte(s)" % (used, size)
            )
        self.write_zero_bits(size * 8 - used)

    def patch_uint(self, at, value, nbytes, little):
        """Overwrite `nbytes` bytes at bit position `at` (byte aligned)."""
        start = at // 8
        self.buf[start:start + nbytes] = (value & ((1 << (8 * nbytes)) - 1)).to_bytes(
            nbytes, "little" if little else "big"
        )

    def patch_bits(self, at, value, width):
        """Overwrite `width` bits at bit position `at`, MSB first."""
        for i in range(width):
            bit = (value >> (width - 1 - i)) & 1
            byte, off = (at + i) // 8, 7 - (at + i) % 8
            self.buf[byte] = (self.buf[byte] & ~(1 << off)) | (bit << off)

    def checksum(self, algo, start, end, hole_start, hole_end):
        """Checksum `algo` of the output between two bit positions (whole
        bytes); the bytes between `hole_start` and `hole_end` count as zero."""
        return _pb_checksum(algo, self.buf, start // 8, end // 8, hole_start // 8, hole_end // 8)

    def utf8_bytes(self, text):
        try:
            return text.encode("utf-8")
        except UnicodeEncodeError:
            raise self.error(PbError.TEXT, "the string is not valid Unicode") from None

    def text_bytes(self, text, enc):
        """`text` in encoding `enc` (see PbReader.text)."""
        try:
            return text.encode(_PB_ENCODINGS[enc])
        except UnicodeEncodeError:
            raise self.error(PbError.TEXT, "the string is not valid %s" % _PB_ENCODINGS[enc]) from None

    def write_varint(self, kind, v):
        """One variable-length integer (see PbReader.read_varint)."""
        v &= (1 << 64) - 1
        if kind == 5:
            if v < 0x80:
                self.write_uint(v, 1, False)
            elif v <= 0x7FFF:
                self.write_uint(v | 0x8000, 2, False)
            else:
                raise self.error(PbError.RANGE, "%d does not fit in a varint15" % v)
            return
        if kind == 4:
            for n, code in ((1, 0), (2, 1), (4, 2), (8, 3)):
                if v < 1 << (8 * n - 2):
                    self.write_uint(v | (code << (8 * n - 2)), n, False)
                    return
            raise self.error(PbError.RANGE, "%d does not fit in a QUIC varint" % v)
        if kind == 1:
            x = v - (1 << 64) if v >> 63 else v
            while True:
                b = x & 0x7F
                x >>= 7
                done = (x == 0 and not b & 0x40) or (x == -1 and b & 0x40)
                self.write_uint(b if done else b | 0x80, 1, False)
                if done:
                    return
        if kind == 3:
            groups = [v & 0x7F]
            v >>= 7
            while v:
                groups.append((v & 0x7F) | 0x80)
                v >>= 7
            self.write_bytes(bytes(reversed(groups)))
            return
        if kind == 2:
            v = ((v << 1) ^ (((1 << 64) - 1) if v >> 63 else 0)) & ((1 << 64) - 1)
        while True:
            b = v & 0x7F
            v >>= 7
            self.write_uint(b | 0x80 if v else b, 1, False)
            if not v:
                return

    def check_no_term(self, data, term):
        if bytes(term) in bytes(data):
            raise self.error(PbError.INVALID, "the value contains its terminator")

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


# CRC parameters by algorithm number: width, polynomial (reflected for
# reflected CRCs), initial value, reflected, final XOR.
_PB_CRC = (
    (8, 0x07, 0, False, 0),  # crc8 (CRC-8/SMBUS)
    (16, 0xA001, 0, True, 0),  # crc16_arc
    (16, 0x1021, 0xFFFF, False, 0),  # crc16_ccitt_false (CRC-16/IBM-3740)
    (16, 0x1021, 0, False, 0),  # crc16_xmodem
    (16, 0x8408, 0, True, 0),  # crc16_kermit
    (16, 0xA001, 0xFFFF, True, 0),  # crc16_modbus
    (32, 0xEDB88320, 0xFFFFFFFF, True, 0xFFFFFFFF),  # crc32 (CRC-32/ISO-HDLC)
    (32, 0x82F63B78, 0xFFFFFFFF, True, 0xFFFFFFFF),  # crc32c (CRC-32/ISCSI)
)


def _pb_checksum(algo, buf, start, end, hole_start, hole_end):
    """Checksum `algo` of buf[start:end] with buf[hole_start:hole_end] as
    zeros. 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8,
    12: sum16, 13: sum32_fold16."""
    data = bytearray(buf[start:end])
    for i in range(max(hole_start, start), min(hole_end, end)):
        data[i - start] = 0
    if algo < 8:
        width, poly, crc, reflected, xorout = _PB_CRC[algo]
        mask = (1 << width) - 1
        for b in data:
            if reflected:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
            else:
                crc ^= b << (width - 8)
                for _ in range(8):
                    crc = ((crc << 1) ^ poly if crc & (1 << (width - 1)) else crc << 1) & mask
        return (crc ^ xorout) & mask
    if algo == 8:
        total = sum((b << 8) if i % 2 == 0 else b for i, b in enumerate(data))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF
    if algo == 9:
        a = b = 0
        for x in data:
            a = (a + x) % 255
            b = (b + a) % 255
        return (b << 8) | a
    if algo == 10:
        return sum(data) & 0xFF
    if algo == 12:
        return sum(data) & 0xFFFF
    if algo == 13:
        total = sum(b << (8 * (3 - i % 4)) for i, b in enumerate(data)) & 0xFFFFFFFF
        return ((total >> 16) + (total & 0xFFFF)) & 0xFFFF
    x = 0
    for b in data:
        x ^= b
    return x


def _pb_json_hex(b):
    """Bytes as a JSON string of hex digits (for to_json)."""
    return '"' + bytes(b).hex() + '"'


_PB_ENCODINGS = ("utf-8", "ascii", "latin-1", "utf-16-le", "utf-16-be")


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
