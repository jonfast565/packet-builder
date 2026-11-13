// ---- packet-builder runtime -------------------------------------------------

/// What went wrong while decoding or encoding.
public enum PbErrorKind: String {
    /// The input ended before the packet did; `neededBits` more would help.
    case incomplete
    /// The data is malformed: a bad length, a missing terminator inside a
    /// window, nesting that is too deep, ...
    case invalid
    /// A value does not fit in its field.
    case range
    /// A string is not valid text, or contains a NUL where none is allowed.
    case text
    /// A length, derived field or checksum does not match the data.
    case mismatch
    /// A value breaks a declared constraint.
    case constraint
}

public struct PbError: Swift.Error, CustomStringConvertible, Equatable {
    public var kind: PbErrorKind
    public var message: String
    /// Where it happened: `Packet.field[index].field`.
    public var path: String
    public var bitOffset: Int
    /// For `incomplete`: the least number of extra input bits needed.
    public var neededBits: Int

    public var description: String {
        if path.isEmpty {
            return "\(message) (at bit \(bitOffset))"
        }
        return "\(path): \(message) (at bit \(bitOffset))"
    }
}

/// Nested packets deeper than this are rejected.
public let pbMaxDepth = 64

/// One packet being decoded or encoded, with the field it is working on.
struct PbFrame {
    var packet: String
    var field: String
    var index: Int?
}

/// The packets being decoded or encoded, innermost last: the path reported
/// in errors.
struct PbTrace {
    var frames: [PbFrame] = []

    mutating func enter(_ packet: String) -> Bool {
        frames.append(PbFrame(packet: packet, field: "", index: nil))
        return frames.count <= pbMaxDepth
    }

    mutating func leave() {
        if !frames.isEmpty {
            frames.removeLast()
        }
    }

    mutating func at(_ field: String) {
        if !frames.isEmpty {
            frames[frames.count - 1].field = field
            frames[frames.count - 1].index = nil
        }
    }

    mutating func atIndex(_ index: Int) {
        if !frames.isEmpty {
            frames[frames.count - 1].index = index
        }
    }

    func path() -> String {
        var out = ""
        if let first = frames.first {
            out += first.packet
        }
        for f in frames {
            if f.field.isEmpty {
                break
            }
            out += "." + f.field
            if let i = f.index {
                out += "[\(i)]"
            }
        }
        return out
    }
}

let pbHexDigits: [Character] = Array("0123456789abcdef")

/// `"0a0b"`: bytes as a JSON string of hex digits (for `toJson`).
public func pbJsonHex<S: Sequence>(_ b: S) -> String where S.Element == UInt8 {
    var out = "\""
    for x in b {
        out.append(pbHexDigits[Int(x >> 4)])
        out.append(pbHexDigits[Int(x & 15)])
    }
    out += "\""
    return out
}

/// A JSON string literal (for `toJson`).
public func pbJsonStr(_ s: String) -> String {
    var out = "\""
    for c in s.unicodeScalars {
        switch c {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        default:
            if c.value < 0x20 {
                out += "\\u00"
                out.append(pbHexDigits[Int(c.value >> 4)])
                out.append(pbHexDigits[Int(c.value & 15)])
            } else {
                out.unicodeScalars.append(c)
            }
        }
    }
    out += "\""
    return out
}

/// Decoding from a buffer that may not hold the whole packet yet (a stream).
public enum PbStatus<T> {
    /// The value, and the bytes it took.
    case done(T, Int)
    /// At least this many more bytes are needed.
    case incomplete(Int)
}

/// Where a reader was before `PbReader.jump`.
public struct PbJump {
    let pos: Int
    let limit: Int
    let windows: Int
}

/// `a * b`, or nil when it does not fit in an Int.
func pbMulOrNil(_ a: Int, _ b: Int) -> Int? {
    let r = a.multipliedReportingOverflow(by: b)
    return r.overflow ? nil : r.partialValue
}

/// `a * b`, saturated at Int.max.
func pbSatMul(_ a: Int, _ b: Int) -> Int {
    return pbMulOrNil(a, b) ?? Int.max
}

// @versions{
/// `v` if it is one of the versions `min...latest`.
func pbCheckVersion(_ v: Int64, _ min: Int, _ latest: Int) -> String? {
    if v < Int64(min) || v > Int64(latest) {
        return "version \(v) is not one of the versions \(min)..\(latest)"
    }
    return nil
}
// @versions}

/// Whether `raw` is valid UTF-8 (no overlong forms, surrogates or values
/// past U+10FFFF).
func pbValidUtf8<C: Collection>(_ raw: C) -> Bool where C.Element == UInt8 {
    var it = raw.makeIterator()
    while let b0 = it.next() {
        if b0 < 0x80 {
            continue
        }
        var need = 0
        var lo: UInt8 = 0x80
        var hi: UInt8 = 0xbf
        switch b0 {
        case 0xc2...0xdf: need = 1
        case 0xe0: need = 2; lo = 0xa0
        case 0xe1...0xec, 0xee...0xef: need = 2
        case 0xed: need = 2; hi = 0x9f
        case 0xf0: need = 3; lo = 0x90
        case 0xf1...0xf3: need = 3
        case 0xf4: need = 3; hi = 0x8f
        default: return false
        }
        for k in 0..<need {
            guard let b = it.next() else { return false }
            if k == 0 {
                if b < lo || b > hi { return false }
            } else if b < 0x80 || b > 0xbf {
                return false
            }
        }
    }
    return true
}

/// Input read on demand (a file, a stream that can seek): `count` bytes,
/// loaded a page at a time by `fetch(offset, buf)`, which fills `buf` with the
/// bytes at `offset` or throws. Only the pages a decode touches are fetched:
/// fields a view skips are never read. Slices a reader returns from a source
/// are copies, so loading more pages never copies the input.
public final class PbSource {
    var buf: [UInt8]
    let page: Int
    var loaded: [Bool]
    let fetch: (Int, UnsafeMutableRawBufferPointer) throws -> Void

    /// A source of `count` bytes read in pages of `page` bytes.
    public init(count: Int, page: Int, fetch: @escaping (Int, UnsafeMutableRawBufferPointer) throws -> Void) {
        self.page = Swift.max(page, 1)
        buf = [UInt8](repeating: 0, count: count)
        loaded = [Bool](repeating: false, count: (count + self.page - 1) / self.page)
        self.fetch = fetch
    }

    /// A source reading `file`, which must be able to seek.
    @available(macOS 10.15.4, iOS 13.4, tvOS 13.4, watchOS 6.2, *)
    public convenience init(file: FileHandle) throws {
        let count = Int(try file.seekToEnd())
        self.init(count: count, page: 4096) { at, buf in
            try file.seek(toOffset: UInt64(at))
            guard let got = try file.read(upToCount: buf.count), got.count == buf.count else {
                throw PbError(kind: .incomplete, message: "the file ended early", path: "", bitOffset: at * 8, neededBits: 0)
            }
            buf.copyBytes(from: got)
        }
    }

    public var count: Int {
        return buf.count
    }

    /// Fetch the pages holding bytes `start..<start + n` that are not loaded yet.
    func load(_ start: Int, _ n: Int) throws {
        if n <= 0 {
            return
        }
        for p in (start / page)...((start + n - 1) / page) where !loaded[p] {
            let from = p * page
            let to = Swift.min(from + page, buf.count)
            let fetch = self.fetch
            try buf.withUnsafeMutableBytes { try fetch(from, UnsafeMutableRawBufferPointer(rebasing: $0[from..<to])) }
            loaded[p] = true
        }
    }
}

/// Reads integers of any bit width (MSB-first) and byte-aligned values.
public final class PbReader {
    let data: [UInt8]
    let src: PbSource? // nil when reading a buffer
    let len: Int // input size in bytes
    var pos = 0 // in bits
    var limit: Int // end of the readable data in bits (a window inside `data`)
    var windows = 0 // windows open
    var trace = PbTrace()
    var version = 0 // protocol version; 0 until set

    public init(_ data: [UInt8]) {
        self.data = data
        self.src = nil
        self.len = data.count
        self.limit = data.count * 8
    }

    /// A reader that fetches its input from `source` as it goes.
    public init(source: PbSource) {
        self.data = []
        self.src = source
        self.len = source.count
        self.limit = source.count * 8
    }

    /// The input, with bytes `start..<start + n` (which `need` has checked
    /// exist) loaded.
    func input(_ start: Int, _ n: Int) throws -> [UInt8] {
        guard let src = src else {
            return data
        }
        do {
            try src.load(start, n)
        } catch {
            throw self.error(.invalid, "cannot read the input: \(error)")
        }
        return src.buf
    }

    /// Input bytes `start..<end` as a slice: shared with a buffer, copied from a source.
    func slice(_ d: [UInt8], _ start: Int, _ end: Int) -> ArraySlice<UInt8> {
        return src == nil ? d[start..<end] : ArraySlice(Array(d[start..<end]))
    }

    /// Where `term` first starts in input bytes `start..<end`.
    func find(_ start: Int, _ end: Int, _ term: [UInt8]) throws -> Int? {
        guard let src = src else {
            return pbFind(data, start, end, term)
        }
        // Page by page, so a long input is only read up to the terminator.
        var from = start
        while from < end {
            let to = Swift.min((from / src.page + 1) * src.page + term.count - 1, end)
            if let at = pbFind(try input(from, to - from), from, to, term) {
                return at
            }
            if to == end {
                break
            }
            from = to + 1 - term.count
        }
        return nil
    }

    // @versions{
    /// The protocol version (`version`), or `latest` while none is set.
    public func versionOr(_ latest: Int) -> Int64 {
        return Int64(version == 0 ? latest : version)
    }

    /// Decode as protocol version `v`, which must be in `min...latest`.
    public func setVersion(_ v: Int64, _ min: Int, _ latest: Int) throws {
        if let m = pbCheckVersion(v, min, latest) {
            throw error(.constraint, m)
        }
        version = Int(v)
    }
    // @versions}

    public func positionBits() -> Int {
        return pos
    }

    public func remainingBits() -> Int {
        return limit - pos
    }

    /// Whole bytes left before the end of the window or input (`remaining`).
    public func remainingBytes() -> Int64 {
        return Int64(remainingBits() / 8)
    }

    public func error(_ kind: PbErrorKind, _ message: String) -> PbError {
        return PbError(kind: kind, message: message, path: trace.path(), bitOffset: pos, neededBits: 0)
    }

    /// `bits` more bits are needed than are left.
    func short(_ bits: Int, _ what: String) -> PbError {
        if windows == 0 {
            var e = error(
                .incomplete,
                "unexpected end of data: \(what) needs \(bits) more bit(s), \(remainingBits()) left")
            e.neededBits = bits - remainingBits()
            return e
        }
        return error(.invalid, "\(what) needs \(bits) bit(s) but its window has \(remainingBits()) left")
    }

    func need(_ bits: Int) throws {
        if bits > remainingBits() {
            throw short(bits, "the field")
        }
    }

    public func enter(_ packet: String) throws {
        if !trace.enter(packet) {
            throw error(.invalid, "packets nested more than \(pbMaxDepth) deep")
        }
    }

    public func leave() {
        trace.leave()
    }

    public func at(_ field: String) {
        trace.at(field)
    }

    public func atIndex(_ index: Int) {
        trace.atIndex(index)
    }

    /// Restrict reading to the next `bytes` bytes; returns the previous
    /// limit for `popLimit`.
    public func pushLimit(_ bytes: Int64) throws -> Int {
        if bytes < 0 {
            throw error(.invalid, "negative size \(bytes)")
        }
        let bits = pbSatMul(Int(truncatingIfNeeded: bytes), 8)
        if bits > remainingBits() {
            throw short(bits, "the window")
        }
        let saved = limit
        limit = pos + bits
        windows += 1
        return saved
    }

    /// Skip what is left of the current window and restore `saved`; with
    /// `exact`, bytes left over are an error.
    public func popLimit(_ saved: Int, _ exact: Bool) throws {
        if exact && remainingBits() > 0 {
            throw error(.invalid, "\(remainingBits()) bit(s) left over in a field that must fill its size")
        }
        pos = limit
        limit = saved
        windows -= 1
    }

    /// Read from `offset` bytes after bit `from` (the packet start, or 0 for
    /// the start of the input) until `jumpBack`; windows do not apply there.
    public func jump(_ from: Int, _ offset: Int64) throws -> PbJump {
        if offset < 0 || from % 8 != 0 {
            throw error(.invalid, "bad offset \(offset) (from bit \(from))")
        }
        let off = pbSatMul(Int(truncatingIfNeeded: offset), 8)
        if off > len * 8 - from {
            throw error(.invalid, "offset \(offset) is past the end of the input")
        }
        let saved = PbJump(pos: pos, limit: limit, windows: windows)
        pos = from + off
        limit = len * 8
        windows = 0
        return saved
    }

    /// Return to where `jump` left.
    public func jumpBack(_ saved: PbJump) {
        pos = saved.pos
        limit = saved.limit
        windows = saved.windows
    }

    public func readBits(_ width: Int) throws -> UInt64 {
        try need(width)
        let data = try input(pos >> 3, ((pos + width + 7) >> 3) - (pos >> 3))
        var v: UInt64 = 0
        var left = width
        while left > 0 {
            let byte = data[pos >> 3]
            let off = pos & 7
            let take = Swift.min(8 - off, left)
            let bits = (byte >> UInt8(8 - off - take)) & UInt8((1 << take) - 1)
            v = (v << UInt64(take)) | UInt64(bits)
            pos += take
            left -= take
        }
        return v
    }

    public func readUInt(_ nbytes: Int, _ little: Bool) throws -> UInt64 {
        try need(nbytes * 8)
        let start = pos >> 3
        let data = try input(start, nbytes)
        var v: UInt64 = 0
        for i in 0..<nbytes {
            let b = little ? data[start + nbytes - 1 - i] : data[start + i]
            v = (v << 8) | UInt64(b)
        }
        pos += nbytes * 8
        return v
    }

    public func readBytes(_ n: Int) throws -> [UInt8] {
        return Array(try readSlice(n))
    }

    /// The next `n` bytes, sharing the input's storage (a buffer's, not a source's).
    public func readSlice(_ n: Int) throws -> ArraySlice<UInt8> {
        try need(pbSatMul(n, 8))
        let start = pos >> 3
        let data = try input(start, n)
        pos += n * 8
        return slice(data, start, start + n)
    }

    public func readMac() throws -> [UInt8] {
        return try readBytes(6)
    }

    public func skipBits(_ bits: Int) throws {
        try need(bits)
        pos += bits
    }

    /// Bytes up to (not including) a NUL terminator, which is consumed.
    public func readCString() throws -> [UInt8] {
        return Array(try readCStringSlice())
    }

    /// The bytes before a NUL, sharing the input's storage; the NUL is consumed.
    public func readCStringSlice() throws -> ArraySlice<UInt8> {
        let start = pos >> 3
        if let i = try find(start, limit >> 3, [0]) {
            let data = try input(start, i - start)
            pos = (i + 1) * 8
            return slice(data, start, i)
        }
        throw short(remainingBits() + 8, "the NUL-terminated string")
    }

    /// Validate a decoded element count against the data that is left.
    public func count(_ n: Int64, _ elemBits: Int) throws -> Int {
        if n < 0 {
            throw error(.invalid, "negative length \(n)")
        }
        let k = Int(truncatingIfNeeded: n)
        if elemBits > 0 && k > remainingBits() / elemBits {
            throw short(pbSatMul(k, elemBits), "length \(n)")
        }
        return k
    }

    /// Text in encoding `enc` (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
    /// 4 UTF-16BE); with `padded`, the text ends at the first NUL character.
    public func text<C: Collection>(_ raw: C, _ enc: Int, _ padded: Bool) throws -> String where C.Element == UInt8 {
        let bytes = Array(raw)
        if enc == 3 || enc == 4 {
            if bytes.count % 2 != 0 {
                throw error(.text, "invalid UTF-16 (an odd number of bytes)")
            }
            var units: [UInt16] = []
            var i = 0
            while i < bytes.count {
                let a = UInt16(bytes[i])
                let b = UInt16(bytes[i + 1])
                let u = enc == 3 ? (b << 8) | a : (a << 8) | b
                if padded && u == 0 {
                    break
                }
                units.append(u)
                i += 2
            }
            var out = String.UnicodeScalarView()
            var k = 0
            while k < units.count {
                let u = units[k]
                var scalar: UInt32 = UInt32(u)
                if u >= 0xd800 && u <= 0xdbff {
                    if k + 1 >= units.count || units[k + 1] < 0xdc00 || units[k + 1] > 0xdfff {
                        throw error(.text, "invalid UTF-16")
                    }
                    scalar = 0x10000 + ((UInt32(u) - 0xd800) << 10) + (UInt32(units[k + 1]) - 0xdc00)
                    k += 1
                } else if u >= 0xdc00 && u <= 0xdfff {
                    throw error(.text, "invalid UTF-16")
                }
                guard let s = Unicode.Scalar(scalar) else {
                    throw error(.text, "invalid UTF-16")
                }
                out.append(s)
                k += 1
            }
            return String(out)
        }
        var raw = bytes
        if padded, let n = raw.firstIndex(of: 0) {
            raw.removeSubrange(n...)
        }
        switch enc {
        case 1, 2:
            if enc == 1 && raw.contains(where: { $0 >= 0x80 }) {
                throw error(.text, "invalid ASCII")
            }
            var out = String.UnicodeScalarView()
            for b in raw {
                out.append(Unicode.Scalar(b))
            }
            return String(out)
        default:
            if !pbValidUtf8(raw) {
                throw error(.text, "invalid UTF-8")
            }
            return String(decoding: raw, as: UTF8.self)
        }
    }

    /// One variable-length integer (`kind`: 0 uleb128, 1 sleb128, 2 zigzag,
    /// 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.
    public func readVarint(_ kind: Int) throws -> UInt64 {
        if kind == 5 {
            let first = try readUInt(1, false)
            if first & 0x80 == 0 {
                return first
            }
            return ((first & 0x7f) << 8) | (try readUInt(1, false))
        }
        if kind == 4 {
            let first = try readUInt(1, false)
            let n = 1 << Int(first >> 6)
            var v = first & 0x3f
            if n > 1 {
                v = (v << UInt64(8 * (n - 1))) | (try readUInt(n - 1, false))
            }
            return v
        }
        var v: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            let b = try readUInt(1, false)
            if kind == 3 {
                if v >> 57 != 0 {
                    throw error(.invalid, "the varint does not fit in 64 bits")
                }
                v = (v << 7) | (b & 0x7f)
            } else {
                // The 10th byte holds bit 63 only (and, for sleb128, its sign).
                let lastOk = kind == 1 ? (b & 0x7f == 0 || b & 0x7f == 0x7f) : (b & 0x7e == 0)
                if shift >= 64 || (shift == 63 && (b & 0x80 != 0 || !lastOk)) {
                    throw error(.invalid, "the varint does not fit in 64 bits")
                }
                v |= (b & 0x7f) << shift
            }
            shift += 7
            if b & 0x80 == 0 {
                if kind == 1 && shift < 64 && b & 0x40 != 0 {
                    v |= UInt64.max << shift
                }
                break
            }
        }
        if kind == 2 {
            v = (v >> 1) ^ (0 &- (v & 1))
        }
        return v
    }

    /// Bytes up to `term`, which is consumed. Without it: the rest of the
    /// input when `optional`, otherwise an error.
    public func readUntil(_ term: [UInt8], _ optional: Bool) throws -> [UInt8] {
        return Array(try readUntilSlice(term, optional))
    }

    /// The bytes before `term`, sharing the input's storage (see `readUntil`).
    public func readUntilSlice(_ term: [UInt8], _ optional: Bool) throws -> ArraySlice<UInt8> {
        let start = pos >> 3
        let end = limit >> 3
        if let i = try find(start, end, term) {
            let data = try input(start, i - start)
            pos = (i + term.count) * 8
            return slice(data, start, i)
        }
        if optional {
            let data = try input(start, end - start)
            pos = limit
            return slice(data, start, end)
        }
        throw short(remainingBits() + 8, "the terminated field")
    }

    /// Checksum `algo` of the input between two bit positions (whole bytes);
    /// the bytes between `holeFrom` and `holeTo` count as zero. From a source
    /// that cannot be read, the checksum of zeros (which then fails to match).
    public func checksum(_ algo: Int, _ from: Int, _ to: Int, _ holeFrom: Int, _ holeTo: Int) -> UInt64 {
        guard let src = src else {
            return pbChecksum(algo, data, from / 8, to / 8, holeFrom / 8, holeTo / 8)
        }
        let base = from / 8
        let n = Swift.max(to / 8 - base, 0)
        do {
            try src.load(base, n)
        } catch {
            let hole = { (h: Int) in Swift.max(h / 8 - base, 0) }
            return pbChecksum(algo, [UInt8](repeating: 0, count: n), 0, n, hole(holeFrom), hole(holeTo))
        }
        return pbChecksum(algo, src.buf, from / 8, to / 8, holeFrom / 8, holeTo / 8)
    }
}

/// Where `term` first starts in `d[start..<end]`.
func pbFind(_ d: [UInt8], _ start: Int, _ end: Int, _ term: [UInt8]) -> Int? {
    var i = start
    while i + term.count <= end {
        var hit = true
        for k in 0..<term.count where d[i + k] != term[k] {
            hit = false
            break
        }
        if hit {
            return i
        }
        i += 1
    }
    return nil
}

/// Builds a byte buffer; integers may be written at any bit position.
public final class PbWriter {
    var buf: [UInt8] = []
    var pos = 0 // in bits
    var trace = PbTrace()
    /// Where `buf` goes in the output, in bits (non-zero for `sub` writers).
    var base = 0
    /// Packets placed at an offset (`at`): byte position, bytes and the
    /// field's path. `finish` writes them.
    var placed: [(Int, [UInt8], String)] = []
    var version = 0 // protocol version; 0 until set

    public init() {}

    // @versions{
    /// The protocol version (`version`), or `latest` while none is set.
    public func versionOr(_ latest: Int) -> Int64 {
        return Int64(version == 0 ? latest : version)
    }

    /// Encode as protocol version `v`, which must be in `min...latest`.
    public func setVersion(_ v: Int64, _ min: Int, _ latest: Int) throws {
        if let m = pbCheckVersion(v, min, latest) {
            throw error(.constraint, m)
        }
        version = Int(v)
    }

    /// The version a value carries in-band: used unless one is set already.
    public func adoptVersion(_ v: Int64, _ min: Int, _ latest: Int) throws {
        if version == 0 {
            try setVersion(v, min, latest)
        }
    }
    // @versions}

    public func positionBits() -> Int {
        return pos
    }

    public func error(_ kind: PbErrorKind, _ message: String) -> PbError {
        return PbError(kind: kind, message: message, path: trace.path(), bitOffset: pos, neededBits: 0)
    }

    public func enter(_ packet: String) throws {
        if !trace.enter(packet) {
            throw error(.invalid, "packets nested more than \(pbMaxDepth) deep")
        }
    }

    public func leave() {
        trace.leave()
    }

    public func at(_ field: String) {
        trace.at(field)
    }

    public func atIndex(_ index: Int) {
        trace.atIndex(index)
    }

    public func writeBits(_ value: UInt64, _ width: Int) {
        var left = width
        while left > 0 {
            if pos & 7 == 0 {
                buf.append(0)
            }
            let off = pos & 7
            let take = Swift.min(8 - off, left)
            let bits = UInt8(truncatingIfNeeded: (value >> UInt64(left - take)) & ((1 << UInt64(take)) - 1))
            buf[buf.count - 1] |= bits << UInt8(8 - off - take)
            pos += take
            left -= take
        }
    }

    public func writeUInt(_ value: UInt64, _ nbytes: Int, _ little: Bool) {
        for i in 0..<nbytes {
            let shift = little ? 8 * i : 8 * (nbytes - 1 - i)
            buf.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
        pos += nbytes * 8
    }

    public func writeBytes<C: Collection>(_ data: C) where C.Element == UInt8 {
        buf.append(contentsOf: data)
        pos += data.count * 8
    }

    /// A MAC address: exactly 6 bytes.
    public func writeMac(_ mac: [UInt8]) throws {
        if mac.count != 6 {
            throw error(.range, "a MAC address has 6 bytes, not \(mac.count)")
        }
        writeBytes(mac)
    }

    public func writeZeroBits(_ bits: Int) {
        if pos & 7 == 0 && bits >= 8 {
            buf.append(contentsOf: repeatElement(0, count: bits / 8))
            pos += bits / 8 * 8
            writeBits(0, bits % 8)
            return
        }
        for _ in 0..<(bits / 32) {
            writeBits(0, 32)
        }
        writeBits(0, bits % 32)
    }

    /// `n` (at least 0) elements of `bits` zero bits.
    public func writeZeroCount(_ n: Int64, _ bits: Int) throws {
        guard let total = pbMulOrNil(Int(truncatingIfNeeded: Swift.max(n, 0)), bits) else {
            throw error(.range, "\(n) padding elements are too many")
        }
        writeZeroBits(total)
    }

    /// The output, with every placed packet written at its offset: past the
    /// end (zero-filling the gap), or over bytes that must already match.
    public func finish() throws -> [UInt8] {
        let order = placed.enumerated().sorted { a, b in
            a.element.0 != b.element.0 ? a.element.0 < b.element.0 : a.offset < b.offset
        }
        placed = []
        for (_, (at, bytes, path)) in order {
            // The output reaches the offset even when the packet is empty.
            if buf.count < at {
                buf.append(contentsOf: repeatElement(0, count: at - buf.count))
            }
            for (i, b) in bytes.enumerated() {
                let k = at + i
                if k < buf.count {
                    if buf[k] != b {
                        throw PbError(
                            kind: .mismatch,
                            message: "the packet placed at byte \(at) does not match the bytes already there",
                            path: path, bitOffset: k * 8, neededBits: 0)
                    }
                } else {
                    buf.append(b)
                }
            }
        }
        return buf
    }

    /// A writer for a packet placed `offset` bytes after bit `from` of this
    /// writer (the packet start), or after the start of the output (`root`).
    public func sub(_ from: Int, _ offset: Int64, _ root: Bool) throws -> PbWriter {
        let start = root ? 0 : base + from
        if offset < 0 || start % 8 != 0 {
            throw error(.range, "bad offset \(offset) (from bit \(start))")
        }
        let w = PbWriter()
        let off = pbSatMul(Int(truncatingIfNeeded: offset), 8)
        w.base = off > Int.max - start ? Int.max & ~7 : off + start
        w.trace = trace
        w.version = version
        return w
    }

    /// Keep what `sub` wrote, for `finish`.
    public func place(_ sub: PbWriter) {
        placed.append((sub.base / 8, sub.buf, trace.path()))
        placed.append(contentsOf: sub.placed)
    }

    /// End a window of `size` bytes that started at bit `start`: the content
    /// must fit (and fill it when `exact`); the rest is zero-filled.
    public func endWindow(_ start: Int, _ size: Int64, _ exact: Bool) throws {
        let used = pos - start
        let room = pbSatMul(Int(truncatingIfNeeded: Swift.max(size, 0)), 8)
        if size < 0 || used > room {
            throw error(.range, "the content takes \(used) bit(s), more than its size of \(size) byte(s)")
        }
        if exact && used != room {
            throw error(.mismatch, "the content takes \(used) bit(s) but must fill its \(size) byte(s)")
        }
        writeZeroBits(room - used)
    }

    /// Overwrite `nbytes` bytes at bit position `at` (byte aligned).
    public func patchUInt(_ at: Int, _ value: UInt64, _ nbytes: Int, _ little: Bool) {
        for i in 0..<nbytes {
            let shift = little ? 8 * i : 8 * (nbytes - 1 - i)
            buf[at / 8 + i] = UInt8(truncatingIfNeeded: value >> UInt64(shift))
        }
    }

    /// Overwrite `width` bits at bit position `at`, MSB first.
    public func patchBits(_ at: Int, _ value: UInt64, _ width: Int) {
        for i in 0..<width {
            let bit = UInt8(truncatingIfNeeded: (value >> UInt64(width - 1 - i)) & 1)
            let byte = (at + i) / 8
            let off = UInt8(7 - (at + i) % 8)
            buf[byte] = (buf[byte] & ~(1 << off)) | (bit << off)
        }
    }

    /// Checksum `algo` of the output between two bit positions (whole
    /// bytes); the bytes between `holeFrom` and `holeTo` count as zero.
    public func checksum(_ algo: Int, _ from: Int, _ to: Int, _ holeFrom: Int, _ holeTo: Int) -> UInt64 {
        return pbChecksum(algo, buf, from / 8, to / 8, holeFrom / 8, holeTo / 8)
    }

    /// One variable-length integer (see `PbReader.readVarint`).
    public func writeVarint(_ kind: Int, _ value: UInt64) throws {
        switch kind {
        case 5:
            if value > 0x7fff {
                throw error(.range, "\(value) does not fit in a varint15")
            }
            if value < 0x80 {
                writeUInt(value, 1, false)
            } else {
                writeUInt(value | 0x8000, 2, false)
            }
        case 4:
            var n = 0
            switch value {
            case 0...0x3f: n = 1
            case 0x40...0x3fff: n = 2
            case 0x4000...0x3fff_ffff: n = 4
            case 0x4000_0000...0x3fff_ffff_ffff_ffff: n = 8
            default: throw error(.range, "\(value) does not fit in a QUIC varint")
            }
            writeUInt(value | (UInt64(n.trailingZeroBitCount) << UInt64(8 * n - 2)), n, false)
        case 1:
            var v = Int64(bitPattern: value)
            while true {
                let b = UInt64(bitPattern: v & 0x7f)
                v >>= 7
                let done = (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0)
                writeUInt(done ? b : b | 0x80, 1, false)
                if done {
                    break
                }
            }
        case 3:
            var groups: [UInt64] = [value & 0x7f]
            var v = value >> 7
            while v != 0 {
                groups.append((v & 0x7f) | 0x80)
                v >>= 7
            }
            for g in groups.reversed() {
                writeUInt(g, 1, false)
            }
        default:
            var v = kind == 2 ? (value << 1) ^ UInt64(bitPattern: Int64(bitPattern: value) >> 63) : value
            while true {
                let b = v & 0x7f
                v >>= 7
                writeUInt(v != 0 ? b | 0x80 : b, 1, false)
                if v == 0 {
                    break
                }
            }
        }
    }

    /// The bytes of `s` in encoding `enc` (see `PbReader.text`).
    public func text(_ s: String, _ enc: Int) throws -> [UInt8] {
        switch enc {
        case 1, 2:
            let max: UInt32 = enc == 1 ? 0x7f : 0xff
            var out: [UInt8] = []
            for c in s.unicodeScalars {
                if c.value > max {
                    throw error(.text, "U+\(String(c.value, radix: 16)) is not \(enc == 1 ? "ASCII" : "Latin-1")")
                }
                out.append(UInt8(truncatingIfNeeded: c.value))
            }
            return out
        case 3, 4:
            var out: [UInt8] = []
            for u in s.utf16 {
                let hi = UInt8(truncatingIfNeeded: u >> 8)
                let lo = UInt8(truncatingIfNeeded: u)
                if enc == 3 {
                    out.append(lo)
                    out.append(hi)
                } else {
                    out.append(hi)
                    out.append(lo)
                }
            }
            return out
        default:
            return Array(s.utf8)
        }
    }

    /// A terminated value must not contain its terminator.
    public func checkNoTerm<C: Collection>(_ bytes: C, _ term: [UInt8]) throws where C.Element == UInt8 {
        let b = Array(bytes)
        var i = 0
        while i + term.count <= b.count {
            if Array(b[i..<i + term.count]) == term {
                throw error(.invalid, "the value contains its terminator")
            }
            i += 1
        }
    }

    public func checkFits(_ len: Int, _ size: Int64) throws {
        if size < 0 || Int64(len) > size {
            throw error(.range, "\(len) byte(s) do not fit in \(size)")
        }
    }

    public func checkNoNul(_ bytes: [UInt8]) throws {
        if bytes.contains(0) {
            throw error(.text, "the string contains a NUL byte")
        }
    }

    public func checkLen(_ actual: Int, _ expected: Int64) throws {
        if expected < 0 || Int64(actual) != expected {
            throw error(.mismatch, "\(actual) element(s) but the length expression says \(expected)")
        }
    }

    public func checkU(_ v: UInt64, _ width: Int) throws {
        if width < 64 && v >> UInt64(width) != 0 {
            throw error(.range, "value \(v) does not fit in \(width) bit(s)")
        }
    }

    public func checkI(_ v: Int64, _ width: Int) throws {
        if width < 64 {
            let lo = -(Int64(1) << Int64(width - 1))
            let hi = (Int64(1) << Int64(width - 1)) - 1
            if v < lo || v > hi {
                throw error(.range, "value \(v) does not fit in \(width) signed bit(s)")
            }
        }
    }
}

/// CRC parameters by algorithm number: width, polynomial (reflected for
/// reflected CRCs), initial value, reflected, final XOR.
let pbCrc: [(Int, UInt64, UInt64, Bool, UInt64)] = [
    (8, 0x07, 0, false, 0), // crc8 (CRC-8/SMBUS)
    (16, 0xa001, 0, true, 0), // crc16_arc
    (16, 0x1021, 0xffff, false, 0), // crc16_ccitt_false (CRC-16/IBM-3740)
    (16, 0x1021, 0, false, 0), // crc16_xmodem
    (16, 0x8408, 0, true, 0), // crc16_kermit
    (16, 0xa001, 0xffff, true, 0), // crc16_modbus
    (32, 0xedb8_8320, 0xffff_ffff, true, 0xffff_ffff), // crc32 (CRC-32/ISO-HDLC)
    (32, 0x82f6_3b78, 0xffff_ffff, true, 0xffff_ffff), // crc32c (CRC-32/ISCSI)
]

/// Checksum `algo` of `buf[from..<to]`, with `buf[holeFrom..<holeTo]` as
/// zeros. 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8,
/// 12: sum16, 13: sum32_fold16.
func pbChecksum(_ algo: Int, _ buf: [UInt8], _ from: Int, _ to: Int, _ holeFrom: Int, _ holeTo: Int) -> UInt64 {
    var bytes: [UInt64] = []
    if from < to {
        for i in from..<to {
            bytes.append(i >= holeFrom && i < holeTo || i < 0 || i >= buf.count ? 0 : UInt64(buf[i]))
        }
    }
    switch algo {
    case 0...7:
        let (width, poly, initial, reflected, xorout) = pbCrc[algo]
        let mask: UInt64 = (1 << UInt64(width)) - 1
        var crc = initial
        for b in bytes {
            if reflected {
                crc ^= b
                for _ in 0..<8 {
                    crc = crc & 1 != 0 ? (crc >> 1) ^ poly : crc >> 1
                }
            } else {
                crc ^= b << UInt64(width - 8)
                for _ in 0..<8 {
                    crc = (crc & (1 << UInt64(width - 1)) != 0 ? (crc << 1) ^ poly : crc << 1) & mask
                }
            }
        }
        return (crc ^ xorout) & mask
    case 8:
        var sum: UInt64 = 0
        for (i, b) in bytes.enumerated() {
            sum = sum &+ (i % 2 == 0 ? b << 8 : b)
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return ~sum & 0xffff
    case 9:
        var a: UInt64 = 0
        var b: UInt64 = 0
        for x in bytes {
            a = (a + x) % 255
            b = (b + a) % 255
        }
        return (b << 8) | a
    case 10:
        return bytes.reduce(0) { ($0 + $1) & 0xff }
    case 12:
        return bytes.reduce(0) { ($0 + $1) & 0xffff }
    case 13:
        var sum: UInt64 = 0
        for (i, b) in bytes.enumerated() {
            sum = (sum + (b << UInt64(8 * (3 - i % 4)))) & 0xffff_ffff
        }
        return ((sum >> 16) + (sum & 0xffff)) & 0xffff
    default:
        return bytes.reduce(0) { $0 ^ $1 }
    }
}

/// A frame length computed from a header (`frameLen`): an error when negative.
func pbFrameSize(_ n: Int64) throws -> Int {
    if n < 0 {
        throw PbError(kind: .invalid, message: "negative length \(n)", path: "", bitOffset: 0, neededBits: 0)
    }
    return Int(truncatingIfNeeded: n)
}

/// Padding needed after `offset` bits to reach a multiple of `unit` bits.
func pbPad(_ offset: Int, _ unit: Int) -> Int {
    return (unit - offset % unit) % unit
}

func pbSext(_ v: UInt64, _ width: Int) -> Int64 {
    if width >= 64 {
        return Int64(bitPattern: v)
    }
    if (v >> UInt64(width - 1)) & 1 == 1 {
        return Int64(bitPattern: v | (UInt64.max << UInt64(width)))
    }
    return Int64(bitPattern: v)
}

func pbTrunc(_ v: Int64, _ width: Int, _ signed: Bool) -> Int64 {
    if width >= 64 {
        return v
    }
    let u = UInt64(bitPattern: v) & ((1 << UInt64(width)) - 1)
    return signed ? pbSext(u, width) : Int64(bitPattern: u)
}

func pbDiv(_ a: Int64, _ b: Int64) -> Int64 {
    return b == 0 ? 0 : a.dividedReportingOverflow(by: b).partialValue
}

func pbMod(_ a: Int64, _ b: Int64) -> Int64 {
    return b == 0 ? 0 : a.remainderReportingOverflow(dividingBy: b).partialValue
}

func pbShl(_ a: Int64, _ b: Int64) -> Int64 {
    return b >= 0 && b < 64 ? a &<< b : 0
}

func pbShr(_ a: Int64, _ b: Int64) -> Int64 {
    return b < 0 ? 0 : a >> Swift.min(b, 63)
}

func pbPow(_ base: Int64, _ exp: Int64) -> Int64 {
    if exp < 0 {
        return 0
    }
    var b = base
    var e = UInt64(exp)
    var acc: Int64 = 1
    while e > 0 {
        if e & 1 == 1 {
            acc = acc &* b
        }
        b = b &* b
        e >>= 1
    }
    return acc
}

/// `base ** exp` on floats.
func pbPowF(_ base: Double, _ exp: Double) -> Double {
    return pow(base, exp)
}

/// A float as a 64-bit integer: truncated, saturated at the limits, 0 for NaN.
func pbF2I(_ v: Double) -> Int64 {
    if v.isNaN {
        return 0
    }
    if v >= 9_223_372_036_854_775_808.0 {
        return Int64.max
    }
    if v < -9_223_372_036_854_775_808.0 {
        return Int64.min
    }
    return Int64(v)
}

@inline(__always) func pbI<T: BinaryInteger>(_ v: T) -> Int64 {
    return Int64(truncatingIfNeeded: v)
}

@inline(__always) func pbI<T: BinaryFloatingPoint>(_ v: T) -> Int64 {
    return pbF2I(Double(v))
}

@inline(__always) func pbF<T: BinaryInteger>(_ v: T) -> Double {
    return Double(v)
}

@inline(__always) func pbF<T: BinaryFloatingPoint>(_ v: T) -> Double {
    return Double(v)
}

@inline(__always) func pbB2I(_ v: Bool) -> Int64 {
    return v ? 1 : 0
}

/// Element `i` of an array as i64, 0 when out of range.
func pbIdxI<C: RandomAccessCollection>(_ c: C, _ i: Int64) -> Int64 where C.Index == Int, C.Element: BinaryInteger {
    return i >= 0 && i < Int64(c.count) ? pbI(c[c.startIndex + Int(i)]) : 0
}

func pbIdxI<C: RandomAccessCollection>(_ c: C, _ i: Int64) -> Int64
where C.Index == Int, C.Element: BinaryFloatingPoint {
    return i >= 0 && i < Int64(c.count) ? pbI(c[c.startIndex + Int(i)]) : 0
}

/// Element `i` of an array as f64, 0 when out of range.
func pbIdxF<C: RandomAccessCollection>(_ c: C, _ i: Int64) -> Double where C.Index == Int, C.Element: BinaryInteger {
    return i >= 0 && i < Int64(c.count) ? pbF(c[c.startIndex + Int(i)]) : 0
}

func pbIdxF<C: RandomAccessCollection>(_ c: C, _ i: Int64) -> Double
where C.Index == Int, C.Element: BinaryFloatingPoint {
    return i >= 0 && i < Int64(c.count) ? pbF(c[c.startIndex + Int(i)]) : 0
}

func pbSumI<S: Sequence>(_ s: S) -> Int64 where S.Element: BinaryInteger {
    return s.reduce(Int64(0)) { $0 &+ pbI($1) }
}

func pbProductI<S: Sequence>(_ s: S) -> Int64 where S.Element: BinaryInteger {
    return s.reduce(Int64(1)) { $0 &* pbI($1) }
}

func pbSumF<S: Sequence>(_ s: S) -> Double where S.Element: BinaryInteger {
    return s.reduce(0.0) { $0 + pbF($1) }
}

func pbSumF<S: Sequence>(_ s: S) -> Double where S.Element: BinaryFloatingPoint {
    return s.reduce(0.0) { $0 + pbF($1) }
}

func pbProductF<S: Sequence>(_ s: S) -> Double where S.Element: BinaryInteger {
    return s.reduce(1.0) { $0 * pbF($1) }
}

func pbProductF<S: Sequence>(_ s: S) -> Double where S.Element: BinaryFloatingPoint {
    return s.reduce(1.0) { $0 * pbF($1) }
}

// ---- generated packets ------------------------------------------------------
