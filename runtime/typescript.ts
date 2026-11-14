// ---- packet-builder runtime -------------------------------------------------
//
// Integers of up to 32 bits are `number`s; wider ones are `bigint`s. Every
// integer expression is evaluated as a signed 64-bit `bigint`.

export type PbErrorKind = "incomplete" | "invalid" | "range" | "text" | "mismatch" | "constraint";

/**
 * Thrown when data cannot be decoded or a value cannot be encoded. `kind`
 * says what went wrong, `path` where (`Packet.field[index].field`),
 * `bitOffset` is the reader or writer position, and `neededBits` (for
 * "incomplete") is the least number of extra input bits needed.
 */
export class PbError extends Error {
  /** The input ended before the packet did. */
  static readonly INCOMPLETE = "incomplete";
  /** Malformed data: a bad length, nesting too deep, ... */
  static readonly INVALID = "invalid";
  /** A value does not fit in its field. */
  static readonly RANGE = "range";
  /** A string is not valid text, or contains a NUL where none is allowed. */
  static readonly TEXT = "text";
  /** A length, derived field or checksum does not match the data. */
  static readonly MISMATCH = "mismatch";
  /** A value breaks a declared constraint. */
  static readonly CONSTRAINT = "constraint";

  kind: PbErrorKind;
  detail: string;
  path: string;
  bitOffset: number;
  neededBits: number;

  constructor(kind: PbErrorKind, detail: string, path = "", bitOffset = 0, neededBits = 0) {
    super(`${path ? path + ": " : ""}${detail} (at bit ${bitOffset})`);
    this.name = "PbError";
    this.kind = kind;
    this.detail = detail;
    this.path = path;
    this.bitOffset = bitOffset;
    this.neededBits = neededBits;
  }
}

/** Deepest packet nesting accepted. */
export const PB_MAX_DEPTH = 64;

export interface PbFrame {
  packet: string;
  field: string;
  index: number | null;
}

/** The packets being decoded or encoded, innermost last, each with the
 * field it is working on: the path reported in errors. */
export class PbTrace {
  frames: PbFrame[] = [];
  /** In bits. */
  pos = 0;
  /** Protocol version; 0 until set. */
  version = 0;
  /** Version scope being coded, plus 1 (0 before any). */
  scope = 0;
  /** The scopes left for it, and their versions. */
  scopes: [number, number][] = [];

  // @versions{
  /** The protocol version (`version`), or `latest` while none is set. */
  versionOr(latest: number): number {
    return this.version || latest;
  }

  /** Code as protocol version `v`, which must be in `lo..latest`. */
  setVersion(v: number | bigint, lo: number, latest: number): void {
    const n = Number(v);
    if (!(n >= lo && n <= latest)) {
      throw this.error(PbError.CONSTRAINT, `version ${v} is not one of the versions ${lo}..${latest}`);
    }
    this.version = n;
  }

  /** The version a value carries in-band: used unless one is set already. */
  adoptVersion(v: number | bigint, lo: number, latest: number): void {
    if (!this.version) this.setVersion(v, lo, latest);
  }

  /** Code a packet of version scope `s`: whether a scope was entered (for
   * `leaveScope`). A scope entered from another starts without a version,
   * unless it encloses this one already. */
  enterScope(s: number): boolean {
    s += 1;
    if (this.scope === s) return false;
    let v = this.version;
    if (this.scope !== 0) {
      v = 0;
      for (let i = this.scopes.length - 1; i >= 0; i--) {
        if (this.scopes[i][0] === s) {
          v = this.scopes[i][1];
          break;
        }
      }
    }
    this.scopes.push([this.scope, this.version]);
    this.scope = s;
    this.version = v;
    return true;
  }

  /** After that packet: back to the outer scope and its version. */
  leaveScope(entered: boolean): void {
    if (!entered) return;
    const e = this.scopes.pop() ?? [0, this.version];
    this.scope = e[0];
    this.version = e[1];
  }
  // @versions}

  enter(packet: string): void {
    this.frames.push({ packet, field: "", index: null });
    if (this.frames.length > PB_MAX_DEPTH) {
      throw this.error(PbError.INVALID, `packets nested more than ${PB_MAX_DEPTH} deep`);
    }
  }

  leave(): void {
    this.frames.pop();
  }

  at(field: string): void {
    const f = this.frames[this.frames.length - 1];
    f.field = field;
    f.index = null;
  }

  atIndex(index: number): void {
    this.frames[this.frames.length - 1].index = index;
  }

  path(): string {
    const parts: string[] = this.frames.length ? [this.frames[0].packet] : [];
    for (const f of this.frames) {
      if (!f.field) break;
      parts.push(f.index === null ? f.field : `${f.field}[${f.index}]`);
    }
    return parts.join(".");
  }

  error(kind: PbErrorKind, detail: string): PbError {
    return new PbError(kind, detail, this.path(), this.pos);
  }

  positionBits(): number {
    return this.pos;
  }
}

/** The parts of Node's `fs` module `PbSource.fromFile` uses. */
export interface PbFileSystem {
  fstatSync(fd: number): { size: number };
  readSync(fd: number, buf: Uint8Array, offset: number, length: number, position: number): number;
}

/**
 * Input read on demand (a file, a stream that can seek): `length` bytes,
 * loaded a page at a time by `fetch(offset, buf)`, which fills `buf` with
 * the bytes at `offset` or throws. Only the pages a decode touches are
 * fetched: fields a view skips are never read. Pages stay loaded while the
 * source lives, so zero-copy views remain valid.
 */
export class PbSource {
  /** The whole input; zeros until a page is loaded. */
  readonly buf: Uint8Array;
  readonly page: number;
  readonly loaded: Uint8Array;
  readonly fetch: (offset: number, buf: Uint8Array) => void;

  constructor(length: number, page: number, fetch: (offset: number, buf: Uint8Array) => void) {
    this.page = Math.max(page, 1);
    this.buf = new Uint8Array(length);
    this.loaded = new Uint8Array(Math.ceil(length / this.page));
    this.fetch = fetch;
  }

  /** A source reading the open file `fd` with Node's `fs` module. */
  static fromFile(fs: PbFileSystem, fd: number): PbSource {
    const length = fs.fstatSync(fd).size;
    return new PbSource(length, 4096, (at, buf) => {
      if (fs.readSync(fd, buf, 0, buf.length, at) !== buf.length) {
        throw new Error(`the file is shorter than ${length} bytes`);
      }
    });
  }

  get length(): number {
    return this.buf.length;
  }

  /** Make bytes `start..start + n` (inside the input) loaded; throws what
   * `fetch` throws. */
  load(start: number, n: number): void {
    if (n <= 0) return;
    const page = this.page;
    for (let p = Math.floor(start / page); p <= Math.floor((start + n - 1) / page); p++) {
      if (this.loaded[p]) continue;
      const at = p * page;
      this.fetch(at, this.buf.subarray(at, Math.min(at + page, this.buf.length)));
      this.loaded[p] = 1;
    }
  }
}

/** Reads integers of any bit width (MSB-first) and byte-aligned values. */
export class PbReader extends PbTrace {
  data: Uint8Array;
  /** A source that fills `data` on demand. */
  src: PbSource | null = null;
  /** End of the readable data (a window inside data), in bits. */
  limit: number;
  /** Windows open. */
  windows = 0;

  constructor(data: Uint8Array) {
    super();
    this.data = data;
    this.limit = data.length * 8;
  }

  /** A reader that fetches its input from `src` as it goes. */
  static fromSource(src: PbSource): PbReader {
    const r = new PbReader(src.buf);
    r.src = src;
    return r;
  }

  /** Fetch input bytes `start..start + n` from the source if needed. */
  load(start: number, n: number): void {
    if (!this.src) return;
    try {
      this.src.load(start, n);
    } catch (e) {
      throw this.error(PbError.INVALID, `cannot read the input: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** Where `term` first starts in input bytes `start..end`, or -1. */
  find(term: Uint8Array, start: number, end: number): number {
    if (!this.src) return pbFind(this.data, term, start, end);
    // Page by page, so a long input is only read up to the terminator.
    const page = this.src.page;
    let at = start;
    while (at < end) {
      const to = Math.min((Math.floor(at / page) + 1) * page + term.length - 1, end);
      this.load(at, to - at);
      const found = pbFind(this.data, term, at, to);
      if (found >= 0 || to === end) return found;
      at = to + 1 - term.length;
    }
    return -1;
  }

  remainingBits(): number {
    return this.limit - this.pos;
  }

  /** Whole bytes left before the end of the window or input (`remaining`). */
  remainingBytes(): number {
    return Math.floor((this.limit - this.pos) / 8);
  }

  /** Read from `offset` bytes after bit `start` (the packet start, or 0 for
   * the start of the input) until `jumpBack`; windows do not apply. */
  jump(start: number, offset: bigint): [number, number, number] {
    const target = start + Number(offset) * 8;
    if (offset < 0n || start % 8 !== 0 || target > this.data.length * 8) {
      throw this.error(PbError.INVALID, `offset ${offset} is past the end of the input`);
    }
    const saved: [number, number, number] = [this.pos, this.limit, this.windows];
    this.pos = target;
    this.limit = this.data.length * 8;
    this.windows = 0;
    return saved;
  }

  jumpBack(saved: [number, number, number]): void {
    [this.pos, this.limit, this.windows] = saved;
  }

  /** The error for `bits` more bits than are left. */
  short(bits: number, what: string): PbError {
    const left = this.remainingBits();
    if (this.windows === 0) {
      const e = this.error(
        PbError.INCOMPLETE,
        `unexpected end of data: ${what} needs ${bits} more bit(s), ${left} left`,
      );
      e.neededBits = bits - left;
      return e;
    }
    return this.error(PbError.INVALID, `${what} needs ${bits} bit(s) but its window has ${left} left`);
  }

  need(bits: number): void {
    if (bits > this.remainingBits()) throw this.short(bits, "the field");
  }

  /** Restrict reading to the next `nbytes` bytes; returns the previous limit. */
  pushLimit(nbytes: bigint): number {
    if (nbytes < 0n) throw this.error(PbError.INVALID, `negative size ${nbytes}`);
    if (nbytes * 8n > BigInt(this.remainingBits())) throw this.short(Number(nbytes) * 8, "the window");
    const saved = this.limit;
    this.limit = this.pos + Number(nbytes) * 8;
    this.windows++;
    return saved;
  }

  /** Skip what is left of the current window and restore `saved`; with
   * `exact`, bytes left over are an error. */
  popLimit(saved: number, exact: boolean): void {
    if (exact && this.remainingBits() > 0) {
      throw this.error(
        PbError.INVALID,
        `${this.remainingBits()} bit(s) left over in a field that must fill its size`,
      );
    }
    this.pos = this.limit;
    this.limit = saved;
    this.windows--;
  }

  /** Up to 32 bits, MSB first, as an unsigned number. */
  readBits(width: number): number {
    this.need(width);
    if (this.src) this.load(this.pos >> 3, ((this.pos + width + 7) >> 3) - (this.pos >> 3));
    let v = 0;
    let left = width;
    while (left > 0) {
      const byte = this.data[this.pos >> 3];
      const off = this.pos & 7;
      const take = Math.min(8 - off, left);
      v = v * (1 << take) + ((byte >> (8 - off - take)) & ((1 << take) - 1));
      this.pos += take;
      left -= take;
    }
    return v;
  }

  /** Up to 64 bits, MSB first, as an unsigned bigint. */
  readBitsBig(width: number): bigint {
    if (width <= 32) return BigInt(this.readBits(width));
    this.need(width);
    const hi = this.readBits(width - 32);
    return (BigInt(hi) << 32n) | BigInt(this.readBits(32));
  }

  /** An unsigned integer of up to 4 whole bytes. */
  readUint(nbytes: number, little: boolean): number {
    this.need(nbytes * 8);
    const start = this.pos >> 3;
    if (this.src) this.load(start, nbytes);
    this.pos += nbytes * 8;
    let v = 0;
    for (let i = 0; i < nbytes; i++) {
      const b = this.data[start + (little ? nbytes - 1 - i : i)];
      v = v * 256 + b;
    }
    return v;
  }

  /** An unsigned integer of up to 8 whole bytes. */
  readUintBig(nbytes: number, little: boolean): bigint {
    this.need(nbytes * 8);
    const start = this.pos >> 3;
    if (this.src) this.load(start, nbytes);
    this.pos += nbytes * 8;
    let v = 0n;
    for (let i = 0; i < nbytes; i++) {
      const b = this.data[start + (little ? nbytes - 1 - i : i)];
      v = (v << 8n) | BigInt(b);
    }
    return v;
  }

  readF32(little: boolean): number {
    this.need(32);
    const start = this.pos >> 3;
    if (this.src) this.load(start, 4);
    this.pos += 32;
    return new DataView(this.data.buffer, this.data.byteOffset + start, 4).getFloat32(0, little);
  }

  readF64(little: boolean): number {
    this.need(64);
    const start = this.pos >> 3;
    if (this.src) this.load(start, 8);
    this.pos += 64;
    return new DataView(this.data.buffer, this.data.byteOffset + start, 8).getFloat64(0, little);
  }

  /** The next n bytes, copied. */
  readBytes(n: number): Uint8Array {
    this.need(n * 8);
    const start = this.pos >> 3;
    if (this.src) this.load(start, n);
    this.pos += n * 8;
    return this.data.slice(start, start + n);
  }

  /** The next n bytes as a view of the input (zero-copy). */
  readView(n: number): Uint8Array {
    this.need(n * 8);
    const start = this.pos >> 3;
    if (this.src) this.load(start, n);
    this.pos += n * 8;
    return this.data.subarray(start, start + n);
  }

  skipBits(bits: number): void {
    this.need(bits);
    this.pos += bits;
  }

  readCstring(): Uint8Array {
    const start = this.pos >> 3;
    const end = this.src
      ? this.find(PB_NUL, start, this.limit >> 3)
      : this.data.subarray(0, this.limit >> 3).indexOf(0, start);
    if (end < 0) throw this.short(this.remainingBits() + 8, "the NUL-terminated string");
    this.pos = (end + 1) * 8;
    return this.data.subarray(start, end);
  }

  /** Validate a decoded element count against the data that is left. */
  count(n: bigint, elemBits: number): number {
    if (n < 0n) throw this.error(PbError.INVALID, `negative length ${n}`);
    if (elemBits > 0 && n > BigInt(Math.floor(this.remainingBits() / elemBits))) {
      throw this.short(Number(n) * elemBits, `length ${n}`);
    }
    return Number(n);
  }

  utf8(raw: Uint8Array): string {
    try {
      return PB_UTF8.decode(raw);
    } catch {
      throw this.error(PbError.TEXT, "invalid UTF-8");
    }
  }

  /** Text in encoding `enc` (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
   * 4 UTF-16BE); `padded` cuts it at the first NUL character. */
  text(raw: Uint8Array, enc: number, padded: boolean): string {
    if (enc >= 3) {
      if (raw.length % 2) throw this.error(PbError.TEXT, "invalid UTF-16 (an odd number of bytes)");
      let n = raw.length;
      if (padded) {
        for (let i = 0; i < raw.length; i += 2) {
          if (raw[i] === 0 && raw[i + 1] === 0) {
            n = i;
            break;
          }
        }
      }
      const units: number[] = [];
      for (let i = 0; i < n; i += 2) {
        units.push(enc === 3 ? raw[i] | (raw[i + 1] << 8) : (raw[i] << 8) | raw[i + 1]);
      }
      for (let i = 0; i < units.length; i++) {
        const u = units[i];
        if (u >= 0xd800 && u <= 0xdbff && i + 1 < units.length && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff) {
          i++;
        } else if (u >= 0xd800 && u <= 0xdfff) {
          throw this.error(PbError.TEXT, `invalid ${PB_ENCODINGS[enc]}`);
        }
      }
      let s = "";
      for (let i = 0; i < units.length; i += 4096) s += String.fromCharCode(...units.slice(i, i + 4096));
      return s;
    }
    if (padded) raw = pbUntilNul(raw);
    if (enc === 0) return this.utf8(raw);
    let s = "";
    for (const b of raw) {
      if (enc === 1 && b > 0x7f) throw this.error(PbError.TEXT, "invalid ascii");
      s += String.fromCharCode(b);
    }
    return s;
  }

  /** One variable-length integer (`kind`: 0 uleb128, 1 sleb128, 2 zigzag,
   * 3 vlq, 4 quic, 5 varint15), as its unsigned 64-bit pattern. */
  readVarint(kind: number): bigint {
    if (kind === 5) {
      const first = this.readUint(1, false);
      if ((first & 0x80) === 0) return BigInt(first);
      return BigInt(((first & 0x7f) << 8) | this.readUint(1, false));
    }
    if (kind === 4) {
      const first = this.readUint(1, false);
      const n = 1 << (first >> 6);
      let v = BigInt(first & 0x3f);
      if (n > 1) v = (v << BigInt(8 * (n - 1))) | this.readUintBig(n - 1, false);
      return v;
    }
    let v = 0n;
    let shift = 0;
    for (;;) {
      const b = this.readUint(1, false);
      if (kind === 3) {
        if (v >> 57n) throw this.error(PbError.INVALID, "the varint does not fit in 64 bits");
        v = (v << 7n) | BigInt(b & 0x7f);
      } else {
        // The 10th byte holds bit 63 only (and, for sleb128, its sign).
        const lastOk = kind === 1 ? (b & 0x7f) === 0 || (b & 0x7f) === 0x7f : (b & 0x7e) === 0;
        if (shift >= 64 || (shift === 63 && ((b & 0x80) !== 0 || !lastOk))) {
          throw this.error(PbError.INVALID, "the varint does not fit in 64 bits");
        }
        v |= BigInt(b & 0x7f) << BigInt(shift);
      }
      shift += 7;
      if ((b & 0x80) === 0) {
        if (kind === 1 && shift < 64 && (b & 0x40) !== 0) v |= PB_MASK64 << BigInt(shift);
        break;
      }
    }
    v &= PB_MASK64;
    if (kind === 2) v = (v >> 1n) ^ (-(v & 1n) & PB_MASK64);
    return v;
  }

  /** The bytes before `term`, consuming both. Without the terminator: the
   * rest of the input when `optional`, otherwise an error. A view of the input. */
  readUntilView(term: Uint8Array, optional: boolean): Uint8Array {
    const start = this.pos >> 3;
    const end = this.find(term, start, this.limit >> 3);
    if (end < 0) {
      if (!optional) throw this.short(this.remainingBits() + 8, "the terminated field");
      this.load(start, (this.limit >> 3) - start);
      this.pos = this.limit;
      return this.data.subarray(start, this.limit >> 3);
    }
    this.pos = (end + term.length) * 8;
    return this.data.subarray(start, end);
  }

  /** readUntilView, copied. */
  readUntil(term: Uint8Array, optional: boolean): Uint8Array {
    return this.readUntilView(term, optional).slice();
  }

  /** Checksum `algo` of the input between two bit positions (whole bytes);
   * the bytes between `holeStart` and `holeEnd` count as zero. From a source
   * that cannot be read, the checksum of zeros (which then fails to match). */
  checksum(algo: number, start: number, end: number, holeStart: number, holeEnd: number): number {
    if (this.src) {
      const base = start >> 3;
      const n = Math.max((end >> 3) - base, 0);
      try {
        this.src.load(base, n);
      } catch {
        const hole = (h: number) => Math.max((h >> 3) - base, 0);
        return pbChecksum(algo, new Uint8Array(n), 0, n, hole(holeStart), hole(holeEnd));
      }
    }
    return pbChecksum(algo, this.data, start >> 3, end >> 3, holeStart >> 3, holeEnd >> 3);
  }
}

export interface PbPlaced {
  at: number;
  data: Uint8Array;
  path: string;
}

/** Builds a byte buffer; integers may be written at any bit position. */
export class PbWriter extends PbTrace {
  buf = new Uint8Array(64);
  /** Bytes of `buf` in use. */
  len = 0;
  /** Where buf goes in the output, in bits (sub writers). */
  base = 0;
  /** Packets placed with `at`. */
  placed: PbPlaced[] = [];

  /** Room for `n` more bytes. */
  grow(n: number): void {
    if (this.len + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.len + n) size *= 2;
    const b = new Uint8Array(size);
    b.set(this.buf.subarray(0, this.len));
    this.buf = b;
  }

  /** A writer for a packet placed `offset` bytes after bit `start` of this
   * writer (the packet start), or after the start of the output (`root`). */
  sub(start: number, offset: bigint, root: boolean): PbWriter {
    const from = root ? 0 : this.base + start;
    if (offset < 0n || from % 8 !== 0) throw this.error(PbError.RANGE, `bad offset ${offset} (from bit ${from})`);
    const s = new PbWriter();
    s.version = this.version;
    s.scope = this.scope;
    s.scopes = this.scopes.map((e) => [e[0], e[1]]);
    s.base = from + Number(offset) * 8;
    s.frames = this.frames.map((f) => ({ ...f }));
    return s;
  }

  /** Keep what `s` wrote, for `finish`. */
  place(s: PbWriter): void {
    this.placed.push({ at: s.base >> 3, data: s.buf.slice(0, s.len), path: this.path() });
    this.placed.push(...s.placed);
  }

  /** Up to 64 bits, MSB first. */
  writeBits(value: number | bigint, width: number): void {
    if (width > 32) {
      const x = BigInt.asUintN(width, BigInt(value));
      this.writeBits(Number(x >> 32n), width - 32);
      this.writeBits(Number(x & 0xffffffffn), 32);
      return;
    }
    const x = pbBits(value, width);
    let left = width;
    while (left > 0) {
      if ((this.pos & 7) === 0) {
        this.grow(1);
        this.buf[this.len++] = 0;
      }
      const off = this.pos & 7;
      const take = Math.min(8 - off, left);
      const bits = Math.floor(x / 2 ** (left - take)) & ((1 << take) - 1);
      this.buf[this.len - 1] |= bits << (8 - off - take);
      this.pos += take;
      left -= take;
    }
  }

  /** The low `nbytes` bytes of `value`. */
  writeUint(value: number | bigint, nbytes: number, little: boolean): void {
    this.grow(nbytes);
    pbPut(this.buf, this.len, value, nbytes, little);
    this.len += nbytes;
    this.pos += nbytes * 8;
  }

  writeF32(value: number, little: boolean): void {
    this.grow(4);
    new DataView(this.buf.buffer, this.len, 4).setFloat32(0, value, little);
    this.len += 4;
    this.pos += 32;
  }

  writeF64(value: number, little: boolean): void {
    this.grow(8);
    new DataView(this.buf.buffer, this.len, 8).setFloat64(0, value, little);
    this.len += 8;
    this.pos += 64;
  }

  writeBytes(data: Uint8Array): void {
    this.grow(data.length);
    this.buf.set(data, this.len);
    this.len += data.length;
    this.pos += data.length * 8;
  }

  writeZeroBits(bits: number): void {
    while (bits > 0) {
      const take = Math.min(bits, 32);
      this.writeBits(0, take);
      bits -= take;
    }
  }

  /** The output, with every placed packet written at its offset: past the
   * end (zero-filling the gap), or over bytes that must already match. */
  finish(): Uint8Array {
    const placed = [...this.placed].sort((a, b) => a.at - b.at);
    for (const { at, data, path } of placed) {
      // The output reaches the offset even when the packet is empty.
      if (this.len < at) {
        this.grow(at - this.len);
        this.buf.fill(0, this.len, at);
        this.len = at;
      }
      for (let i = 0; i < data.length; i++) {
        const k = at + i;
        if (k < this.len) {
          if (this.buf[k] !== data[i]) {
            throw new PbError(
              PbError.MISMATCH,
              `the packet placed at byte ${at} does not match the bytes already there`,
              path,
              k * 8,
            );
          }
        } else {
          this.grow(1);
          this.buf[this.len++] = data[i];
        }
      }
    }
    this.placed = [];
    return this.buf.slice(0, this.len);
  }

  /** End a window of `size` bytes that started at bit `start`: the content
   * must fit (and fill it when `exact`); the rest is zero-filled. */
  endWindow(start: number, size: bigint, exact: boolean): void {
    const used = this.pos - start;
    if (size < 0n || BigInt(used) > size * 8n) {
      throw this.error(PbError.RANGE, `the content takes ${used} bit(s), more than its size of ${size} byte(s)`);
    }
    if (exact && BigInt(used) !== size * 8n) {
      throw this.error(PbError.MISMATCH, `the content takes ${used} bit(s) but must fill its ${size} byte(s)`);
    }
    this.writeZeroBits(Number(size) * 8 - used);
  }

  /** Overwrite `nbytes` bytes at bit position `at` (byte aligned). */
  patchUint(at: number, value: number | bigint, nbytes: number, little: boolean): void {
    pbPut(this.buf, at >> 3, value, nbytes, little);
  }

  /** Overwrite `width` bits at bit position `at`, MSB first. */
  patchBits(at: number, value: number | bigint, width: number): void {
    const x = BigInt.asUintN(width, BigInt(value));
    for (let i = 0; i < width; i++) {
      const bit = Number((x >> BigInt(width - 1 - i)) & 1n);
      const byte = (at + i) >> 3;
      const off = 7 - ((at + i) & 7);
      this.buf[byte] = (this.buf[byte] & ~(1 << off)) | (bit << off);
    }
  }

  /** Checksum `algo` of the output between two bit positions (whole bytes);
   * the bytes between `holeStart` and `holeEnd` count as zero. */
  checksum(algo: number, start: number, end: number, holeStart: number, holeEnd: number): number {
    return pbChecksum(algo, this.buf.subarray(0, this.len), start >> 3, end >> 3, holeStart >> 3, holeEnd >> 3);
  }

  utf8Bytes(text: string): Uint8Array {
    if (!pbWellFormed(text)) throw this.error(PbError.TEXT, "the string is not valid Unicode");
    return PB_UTF8_OUT.encode(text);
  }

  /** `text` in encoding `enc` (see PbReader.text). */
  textBytes(text: string, enc: number): Uint8Array {
    if (enc === 0) return this.utf8Bytes(text);
    if (enc >= 3) {
      if (!pbWellFormed(text)) throw this.error(PbError.TEXT, `the string is not valid ${PB_ENCODINGS[enc]}`);
      const out = new Uint8Array(text.length * 2);
      for (let i = 0; i < text.length; i++) {
        const u = text.charCodeAt(i);
        out[2 * i] = enc === 3 ? u & 0xff : u >> 8;
        out[2 * i + 1] = enc === 3 ? u >> 8 : u & 0xff;
      }
      return out;
    }
    const max = enc === 1 ? 0x7f : 0xff;
    const out = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (c > max) throw this.error(PbError.TEXT, `the string is not valid ${PB_ENCODINGS[enc]}`);
      out[i] = c;
    }
    return out;
  }

  /** One variable-length integer (see PbReader.readVarint). */
  writeVarint(kind: number, value: number | bigint): void {
    let v = BigInt.asUintN(64, BigInt(value));
    if (kind === 5) {
      if (v < 0x80n) this.writeUint(v, 1, false);
      else if (v <= 0x7fffn) this.writeUint(v | 0x8000n, 2, false);
      else throw this.error(PbError.RANGE, `${v} does not fit in a varint15`);
      return;
    }
    if (kind === 4) {
      for (const [n, code] of [[1, 0n], [2, 1n], [4, 2n], [8, 3n]] as const) {
        if (v < 1n << BigInt(8 * n - 2)) {
          this.writeUint(v | (code << BigInt(8 * n - 2)), n, false);
          return;
        }
      }
      throw this.error(PbError.RANGE, `${v} does not fit in a QUIC varint`);
    }
    if (kind === 1) {
      let x = BigInt.asIntN(64, v);
      for (;;) {
        const b = x & 0x7fn;
        x >>= 7n;
        const done = (x === 0n && (b & 0x40n) === 0n) || (x === -1n && (b & 0x40n) !== 0n);
        this.writeUint(done ? b : b | 0x80n, 1, false);
        if (done) return;
      }
    }
    if (kind === 3) {
      const groups = [Number(v & 0x7fn)];
      v >>= 7n;
      while (v) {
        groups.push(Number(v & 0x7fn) | 0x80);
        v >>= 7n;
      }
      this.writeBytes(Uint8Array.from(groups.reverse()));
      return;
    }
    if (kind === 2) v = ((v << 1n) ^ (v >> 63n ? PB_MASK64 : 0n)) & PB_MASK64;
    for (;;) {
      const b = v & 0x7fn;
      v >>= 7n;
      this.writeUint(v ? b | 0x80n : b, 1, false);
      if (!v) return;
    }
  }

  checkNoTerm(data: Uint8Array, term: Uint8Array): void {
    if (pbFind(data, term, 0, data.length) >= 0) throw this.error(PbError.INVALID, "the value contains its terminator");
  }

  checkFits(length: number, size: bigint): void {
    if (BigInt(length) > size) throw this.error(PbError.RANGE, `${length} byte(s) do not fit in ${size}`);
  }

  checkNoNul(data: Uint8Array): void {
    if (data.indexOf(0) >= 0) throw this.error(PbError.TEXT, "the string contains a NUL byte");
  }

  checkLen(actual: number, expected: bigint): void {
    if (BigInt(actual) !== expected) {
      throw this.error(PbError.MISMATCH, `${actual} element(s) but the length expression says ${expected}`);
    }
  }

  checkMac(v: Uint8Array): void {
    if (v.length !== 6) throw this.error(PbError.MISMATCH, `${v.length} element(s) but the length expression says 6`);
  }

  /** `v` is an integer that fits in `width` unsigned bits. */
  checkU(v: number | bigint, width: number): void {
    if (typeof v === "number" && !Number.isInteger(v)) {
      throw this.error(PbError.RANGE, `value ${v} is not an integer`);
    }
    const x = BigInt(v);
    if (x < 0n || x >> BigInt(width)) {
      throw this.error(PbError.RANGE, `value ${v} does not fit in ${width} bit(s)`);
    }
  }

  /** `v` is an integer that fits in `width` signed bits. */
  checkI(v: number | bigint, width: number): void {
    if (typeof v === "number" && !Number.isInteger(v)) {
      throw this.error(PbError.RANGE, `value ${v} is not an integer`);
    }
    const x = BigInt(v);
    const half = 1n << BigInt(width - 1);
    if (x < -half || x >= half) {
      throw this.error(PbError.RANGE, `value ${v} does not fit in ${width} signed bit(s)`);
    }
  }
}

const PB_MASK64 = (1n << 64n) - 1n;
const PB_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const PB_UTF8_OUT = new TextEncoder();
const PB_ENCODINGS = ["utf-8", "ascii", "latin-1", "utf-16-le", "utf-16-be"];

/** The low `width` (at most 32) bits of `v`, as an unsigned number. */
function pbBits(v: number | bigint, width: number): number {
  if (typeof v === "bigint") return Number(BigInt.asUintN(width, v));
  const x = v >>> 0;
  return width === 32 ? x : x & ((1 << width) - 1);
}

/** Store the low `nbytes` bytes of `value` at `buf[at]`. */
function pbPut(buf: Uint8Array, at: number, value: number | bigint, nbytes: number, little: boolean): void {
  if (nbytes <= 4 && typeof value === "number") {
    let x = pbBits(value, nbytes * 8);
    for (let i = nbytes - 1; i >= 0; i--) {
      buf[at + (little ? nbytes - 1 - i : i)] = x & 0xff;
      x = Math.floor(x / 256);
    }
    return;
  }
  let x = BigInt.asUintN(nbytes * 8, BigInt(value));
  for (let i = nbytes - 1; i >= 0; i--) {
    buf[at + (little ? nbytes - 1 - i : i)] = Number(x & 0xffn);
    x >>= 8n;
  }
}

/** Index of `term` in `data[from:to]`, or -1. */
const PB_NUL = new Uint8Array([0]);

function pbFind(data: Uint8Array, term: Uint8Array, from: number, to: number): number {
  outer: for (let i = from; i + term.length <= to; i++) {
    for (let j = 0; j < term.length; j++) {
      if (data[i + j] !== term[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/** No unpaired surrogates. */
function pbWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const u = s.charCodeAt(i);
    if (u >= 0xd800 && u <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (u >= 0xdc00 && u <= 0xdfff) {
      return false;
    }
  }
  return true;
}

// CRC parameters by algorithm number: width, polynomial (reflected for
// reflected CRCs), initial value, reflected, final XOR.
const PB_CRC: [number, number, number, boolean, number][] = [
  [8, 0x07, 0, false, 0], // crc8 (CRC-8/SMBUS)
  [16, 0xa001, 0, true, 0], // crc16_arc
  [16, 0x1021, 0xffff, false, 0], // crc16_ccitt_false (CRC-16/IBM-3740)
  [16, 0x1021, 0, false, 0], // crc16_xmodem
  [16, 0x8408, 0, true, 0], // crc16_kermit
  [16, 0xa001, 0xffff, true, 0], // crc16_modbus
  [32, 0xedb88320, 0xffffffff, true, 0xffffffff], // crc32 (CRC-32/ISO-HDLC)
  [32, 0x82f63b78, 0xffffffff, true, 0xffffffff], // crc32c (CRC-32/ISCSI)
];

/** Checksum `algo` of buf[start:end] with buf[holeStart:holeEnd] as zeros.
 * 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8,
 * 12: sum16, 13: sum32_fold16. */
function pbChecksum(algo: number, buf: Uint8Array, start: number, end: number, holeStart: number, holeEnd: number): number {
  const data = buf.slice(start, end);
  for (let i = Math.max(holeStart, start); i < Math.min(holeEnd, end); i++) data[i - start] = 0;
  if (algo < 8) {
    const [width, poly, init, reflected, xorout] = PB_CRC[algo];
    const top = 2 ** (width - 1);
    const mod = 2 ** width;
    let crc = init;
    for (const b of data) {
      if (reflected) {
        crc = (crc ^ b) >>> 0;
        for (let k = 0; k < 8; k++) crc = crc & 1 ? ((crc >>> 1) ^ poly) >>> 0 : crc >>> 1;
      } else {
        crc = (crc ^ (b * 2 ** (width - 8))) >>> 0;
        for (let k = 0; k < 8; k++) {
          crc = crc >= top ? (((crc - top) * 2) ^ poly) >>> 0 : crc * 2;
          crc %= mod;
        }
      }
    }
    return ((crc ^ xorout) >>> 0) % mod;
  }
  if (algo === 8) {
    let total = 0;
    for (let i = 0; i < data.length; i++) total += i % 2 === 0 ? data[i] << 8 : data[i];
    while (total > 0xffff) total = (total & 0xffff) + Math.floor(total / 65536);
    return ~total & 0xffff;
  }
  if (algo === 9) {
    let a = 0;
    let b = 0;
    for (const x of data) {
      a = (a + x) % 255;
      b = (b + a) % 255;
    }
    return (b << 8) | a;
  }
  if (algo === 10 || algo === 12) {
    let total = 0;
    for (const x of data) total += x;
    return algo === 10 ? total & 0xff : total & 0xffff;
  }
  if (algo === 13) {
    let total = 0;
    for (let i = 0; i < data.length; i++) total = (total + data[i] * 2 ** (8 * (3 - (i % 4)))) % 2 ** 32;
    return (Math.floor(total / 65536) + (total & 0xffff)) & 0xffff;
  }
  let x = 0;
  for (const b of data) x ^= b;
  return x;
}

/** Bytes as a JSON string of hex digits (for toJson). */
function pbJsonHex(b: Uint8Array): string {
  let s = '"';
  for (const x of b) s += (x < 16 ? "0" : "") + x.toString(16);
  return s + '"';
}

/** A float for toJson (null when it is not finite). */
function pbJsonF(v: number): string {
  return Number.isFinite(v) ? String(v) : "null";
}

/** Padding needed after `offset` bits to reach a multiple of `unit` bits. */
function pbPad(offset: number, unit: number): number {
  return (unit - (offset % unit)) % unit;
}

function pbUntilNul(raw: Uint8Array): Uint8Array {
  const end = raw.indexOf(0);
  return end < 0 ? raw : raw.subarray(0, end);
}

/** Wrap to a signed 64-bit integer. */
function pbW(v: bigint): bigint {
  return BigInt.asIntN(64, v);
}

/** Any integer as a signed 64-bit bigint. */
function pbI(v: number | bigint): bigint {
  return typeof v === "bigint" ? BigInt.asIntN(64, v) : BigInt(v);
}

/** Sign-extend the low `width` (at most 32) bits of `v`. */
function pbSext(v: number, width: number): number {
  return width >= 32 ? v | 0 : (v << (32 - width)) >> (32 - width);
}

/** The low `width` (at most 32) bits of `v`: two's complement when `signed`. */
function pbTrunc(v: bigint, width: number, signed: boolean): number {
  return Number(signed ? BigInt.asIntN(width, v) : BigInt.asUintN(width, v));
}

function pbDiv(a: bigint, b: bigint): bigint {
  return b === 0n ? 0n : pbW(a / b);
}

function pbMod(a: bigint, b: bigint): bigint {
  return b === 0n ? 0n : a % b;
}

function pbShl(a: bigint, b: bigint): bigint {
  return b < 0n || b > 63n ? 0n : pbW(a << b);
}

function pbShr(a: bigint, b: bigint): bigint {
  return b < 0n ? 0n : a >> (b > 63n ? 63n : b);
}

function pbPow(a: bigint, b: bigint): bigint {
  if (b < 0n) return 0n;
  let r = 1n;
  let x = a;
  for (let e = b; e > 0n; e >>= 1n) {
    if (e & 1n) r = pbW(r * x);
    x = pbW(x * x);
  }
  return r;
}

function pbFPow(a: number, b: number): number {
  // IEEE pow: 1 to any power, and -1 to an infinite one, is 1.
  if (a === 1 || (a === -1 && (b === Infinity || b === -Infinity))) return 1;
  return Math.pow(a, b);
}

function pbFtoi(v: number): bigint {
  if (Number.isNaN(v)) return 0n;
  if (v >= 9.223372036854775807e18) return (1n << 63n) - 1n;
  if (v <= -9.223372036854775808e18) return -(1n << 63n);
  return BigInt(Math.trunc(v));
}

function pbMin<T extends number | bigint>(a: T, b: T): T {
  return b < a ? b : a;
}

function pbMax<T extends number | bigint>(a: T, b: T): T {
  return b > a ? b : a;
}

/** Element `i` of `seq`, or `zero` when out of range. */
function pbAt<T>(seq: ArrayLike<T>, i: bigint, zero: T): T {
  return i >= 0n && i < BigInt(seq.length) ? seq[Number(i)] : zero;
}

function pbSum(seq: ArrayLike<number | bigint>): bigint {
  let s = 0n;
  for (let i = 0; i < seq.length; i++) s = pbW(s + pbI(seq[i]));
  return s;
}

function pbProd(seq: ArrayLike<number | bigint>): bigint {
  let s = 1n;
  for (let i = 0; i < seq.length; i++) s = pbW(s * pbI(seq[i]));
  return s;
}

function pbSumF(seq: ArrayLike<number | bigint>): number {
  let s = 0;
  for (let i = 0; i < seq.length; i++) s += Number(seq[i]);
  return s;
}

function pbProdF(seq: ArrayLike<number | bigint>): number {
  let s = 1;
  for (let i = 0; i < seq.length; i++) s *= Number(seq[i]);
  return s;
}

/** Bytes of `s` in UTF-8 (`len` of a string). */
function pbUtf8Len(s: string): number {
  return PB_UTF8_OUT.encode(s).length;
}

/** Hex digits (whitespace ignored) as bytes. */
export function pbFromHex(hex: string): Uint8Array {
  const h = hex.replace(/\s+/g, "");
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
  return out;
}

/** Bytes as lowercase hex digits. */
export function pbToHex(b: Uint8Array): string {
  return pbJsonHex(b).slice(1, -1);
}

// ---- generated packets ------------------------------------------------------
