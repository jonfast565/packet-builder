    // ---- packet-builder runtime ---------------------------------------------

    /** What went wrong while decoding or encoding. */
    public enum PbErrorKind {
        /** The input ended before the packet did; neededBits() more would help. */
        INCOMPLETE,
        /** Malformed data: a bad length, nesting too deep, ... */
        INVALID,
        /** A value does not fit in its field. */
        RANGE,
        /** A string is not valid text, or contains a NUL where none is allowed. */
        TEXT,
        /** A length, derived field or checksum does not match the data. */
        MISMATCH,
        /** A value breaks a declared constraint. */
        CONSTRAINT;

        /** The kind in lower case ("incomplete"), as the other runtimes name it. */
        public String label() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    /**
     * Decoding from a buffer that may not hold the whole packet yet (a stream):
     * the value and the bytes it took, or how many more bytes are needed at least.
     */
    public record PbStatus<T>(boolean isDone, T value, int consumed, int needed) {
        public static <T> PbStatus<T> done(T value, int consumed) {
            return new PbStatus<>(true, value, consumed, 0);
        }

        public static <T> PbStatus<T> incomplete(int needed) {
            return new PbStatus<>(false, null, 0, needed);
        }
    }

    /** Thrown when data cannot be decoded or a value cannot be encoded. */
    public static final class PbException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final PbErrorKind kind;
        private final String reason;
        private final String path;
        private final long bitOffset;
        private final long neededBits;

        public PbException(PbErrorKind kind, String reason, String path, long bitOffset, long neededBits) {
            super((path.isEmpty() ? "" : path + ": ") + reason + " (at bit " + bitOffset + ")");
            this.kind = kind;
            this.reason = reason;
            this.path = path;
            this.bitOffset = bitOffset;
            this.neededBits = neededBits;
        }

        public PbErrorKind kind() {
            return kind;
        }

        public String reason() {
            return reason;
        }

        /** Where it happened: Packet.field[index].field. */
        public String path() {
            return path;
        }

        public long bitOffset() {
            return bitOffset;
        }

        /** For INCOMPLETE: the least number of extra input bits needed. */
        public long neededBits() {
            return neededBits;
        }
    }

    /**
     * The packets being decoded or encoded, innermost last, each with the
     * field it is working on: the path reported in errors.
     */
    public abstract static class PbTrace {
        /** The deepest packet nesting accepted. */
        public static final int MAX_DEPTH = 64;

        private record Frame(String packet, String field, long index) {}

        private final java.util.ArrayList<Frame> frames = new java.util.ArrayList<>();
        protected long pos; // in bits
        private int version; // protocol version; 0 until set
        private int scope; // version scope being coded, plus 1 (0 before any)
        private final java.util.ArrayList<int[]> scopes = new java.util.ArrayList<>(); // the scopes left for it ({scope, version})

        public long positionBits() {
            return pos;
        }

        public void enter(String packet) {
            frames.add(new Frame(packet, "", -1));
            if (frames.size() > MAX_DEPTH) {
                throw error(PbErrorKind.INVALID, "packets nested more than " + MAX_DEPTH + " deep");
            }
        }

        public void leave() {
            frames.remove(frames.size() - 1);
        }

        /** Start from the frames (and version) of other (for sub writers). */
        protected void copyFrames(PbTrace other) {
            frames.addAll(other.frames);
            version = other.version;
            scope = other.scope;
            scopes.addAll(other.scopes);
        }

        // @versions{
        /** The protocol version ({@code version}), or latest while none is set. */
        public long versionOr(int latest) {
            return version == 0 ? latest : version;
        }

        /** Code as protocol version v, which must be in min..latest. */
        public void setVersion(long v, int min, int latest) {
            if (v < min || v > latest) {
                throw error(PbErrorKind.CONSTRAINT, "version " + v + " is not one of the versions " + min + ".." + latest);
            }
            version = (int) v;
        }

        /** The version a value carries in-band: used unless one is set already. */
        public void adoptVersion(long v, int min, int latest) {
            if (version == 0) {
                setVersion(v, min, latest);
            }
        }

        /**
         * Code a packet of version scope s ({@code Packet::version_scope}): whether a scope was entered
         * (for leaveScope). A scope entered from another starts without a version, unless it encloses
         * this one already.
         */
        public boolean enterScope(int s) {
            s += 1;
            if (scope == s) {
                return false;
            }
            int v = version;
            if (scope != 0) {
                v = 0;
                for (int i = scopes.size() - 1; i >= 0; i--) {
                    if (scopes.get(i)[0] == s) {
                        v = scopes.get(i)[1];
                        break;
                    }
                }
            }
            scopes.add(new int[] {scope, version});
            scope = s;
            version = v;
            return true;
        }

        /** After that packet: back to the outer scope and its version. */
        public void leaveScope(boolean entered) {
            if (!entered) {
                return;
            }
            if (scopes.isEmpty()) {
                scope = 0;
                return;
            }
            int[] e = scopes.remove(scopes.size() - 1);
            scope = e[0];
            version = e[1];
        }
        // @versions}

        public void at(String field) {
            int top = frames.size() - 1;
            frames.set(top, new Frame(frames.get(top).packet(), field, -1));
        }

        public void atIndex(long index) {
            int top = frames.size() - 1;
            Frame f = frames.get(top);
            frames.set(top, new Frame(f.packet(), f.field(), index));
        }

        public String path() {
            StringBuilder sb = new StringBuilder();
            if (!frames.isEmpty()) {
                sb.append(frames.get(0).packet());
            }
            for (Frame f : frames) {
                if (f.field().isEmpty()) {
                    break;
                }
                sb.append('.').append(f.field());
                if (f.index() >= 0) {
                    sb.append('[').append(f.index()).append(']');
                }
            }
            return sb.toString();
        }

        public PbException error(PbErrorKind kind, String reason) {
            return error(kind, reason, 0);
        }

        public PbException error(PbErrorKind kind, String reason, long neededBits) {
            return new PbException(kind, reason, path(), pos, neededBits);
        }
    }

    /** Fills buf with the input bytes at offset, or throws when they cannot be read. */
    @FunctionalInterface
    public interface PbFetch {
        void fetch(long offset, byte[] buf) throws java.io.IOException;
    }

    /**
     * Input read on demand (a file, a channel that can seek): length() bytes,
     * loaded a page at a time by a PbFetch. Only the pages a decode touches
     * are fetched: fields a view skips are never read. Pages stay loaded while
     * the source lives, so zero-copy views into it remain valid.
     */
    public static final class PbSource {
        final byte[] buf;
        final int page;
        private final boolean[] loaded;
        private final PbFetch fetch;

        /** A source of len bytes read in pages of page bytes. */
        public PbSource(long len, int page, PbFetch fetch) {
            this.page = Math.max(page, 1);
            buf = new byte[Math.toIntExact(len)];
            loaded = new boolean[(int) ((len + this.page - 1) / this.page)];
            this.fetch = fetch;
        }

        /** A source reading channel (a {@code FileChannel}, or anything that can seek). */
        public static PbSource fromChannel(java.nio.channels.SeekableByteChannel channel) throws java.io.IOException {
            return new PbSource(channel.size(), 4096, (at, buf) -> {
                channel.position(at);
                java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(buf);
                while (bb.hasRemaining()) {
                    if (channel.read(bb) < 0) {
                        throw new java.io.EOFException("the channel ended early");
                    }
                }
            });
        }

        public long length() {
            return buf.length;
        }

        /** Fetch the pages holding bytes start..start + n that are not loaded yet. */
        void load(long start, long n) throws Exception {
            if (n <= 0) {
                return;
            }
            for (long p = start / page; p <= (start + n - 1) / page; p++) {
                if (loaded[(int) p]) {
                    continue;
                }
                int from = (int) (p * page);
                byte[] tmp = new byte[Math.min(page, buf.length - from)];
                fetch.fetch(from, tmp);
                System.arraycopy(tmp, 0, buf, from, tmp.length);
                loaded[(int) p] = true;
            }
        }
    }

    /** Reads integers of any bit width (MSB-first) and byte-aligned values. */
    public static final class PbReader extends PbTrace {
        private static final byte[] NUL = {0};
        private final byte[] data;
        private final PbSource src; // null when reading a buffer
        private long limit; // end of the readable data in bits (a window inside data)
        private int windows; // windows open

        public PbReader(byte[] data) {
            this.data = data;
            src = null;
            limit = (long) data.length * 8;
        }

        /** A reader that fetches its input from src as it goes. */
        public PbReader(PbSource src) {
            this.src = src;
            data = src.buf;
            limit = (long) data.length * 8;
        }

        /** Make input bytes start..start + n (which need has checked exist) available. */
        private void load(long start, long n) {
            if (src == null) {
                return;
            }
            try {
                src.load(start, n);
            } catch (Exception e) {
                throw error(PbErrorKind.INVALID, "cannot read the input: " + e.getMessage());
            }
        }

        /** Where term first starts in input bytes start..end, or -1. */
        private int find(int start, int end, byte[] term) {
            if (src == null) {
                return scan(start, end, term);
            }
            // Page by page, so a long input is only read up to the terminator.
            for (int from = start; from < end;) {
                int to = (int) Math.min((long) (from / src.page + 1) * src.page + term.length - 1, end);
                load(from, to - from);
                int at = scan(from, to, term);
                if (at >= 0) {
                    return at;
                }
                if (to == end) {
                    break;
                }
                from = to + 1 - term.length;
            }
            return -1;
        }

        private int scan(int start, int end, byte[] term) {
            for (int i = start; i + term.length <= end; i++) {
                boolean hit = true;
                for (int k = 0; k < term.length && hit; k++) {
                    hit = data[i + k] == term[k];
                }
                if (hit) {
                    return i;
                }
            }
            return -1;
        }

        public long remainingBits() {
            return limit - pos;
        }

        /** Whole bytes left before the end of the window or input ({@code remaining}). */
        public long remainingBytes() {
            return (limit - pos) / 8;
        }

        /**
         * Read from offset bytes after bit from (the packet start, or 0 for the
         * start of the input) until jumpBack; windows do not apply there.
         */
        public long[] jump(long from, long offset) {
            if (offset < 0 || from % 8 != 0 || offset > data.length || from + offset * 8 > (long) data.length * 8) {
                throw error(PbErrorKind.INVALID, "offset " + offset + " is past the end of the input");
            }
            long[] saved = {pos, limit, windows};
            pos = from + offset * 8;
            limit = (long) data.length * 8;
            windows = 0;
            return saved;
        }

        /** Return to where jump left. */
        public void jumpBack(long[] saved) {
            pos = saved[0];
            limit = saved[1];
            windows = (int) saved[2];
        }

        /**
         * bits more bits are needed than are left: incomplete input at the top
         * level, invalid data inside a window.
         */
        private PbException shortOf(long bits, String what) {
            if (windows == 0) {
                return error(PbErrorKind.INCOMPLETE, "unexpected end of data: " + what + " needs " + bits
                        + " more bit(s), " + remainingBits() + " left", bits - remainingBits());
            }
            return error(PbErrorKind.INVALID, what + " needs " + bits + " bit(s) but its window has "
                    + remainingBits() + " left");
        }

        private void need(long bits) {
            if (bits < 0 || bits > remainingBits()) {
                throw shortOf(bits, "the field");
            }
        }

        /** Restrict reading to the next n bytes; returns the previous limit. */
        public long pushLimit(long n) {
            if (n < 0) {
                throw error(PbErrorKind.INVALID, "negative size " + n);
            }
            if (n > remainingBits() / 8) {
                throw shortOf(n * 8, "the window");
            }
            long saved = limit;
            limit = pos + n * 8;
            windows++;
            return saved;
        }

        /** Skip what is left of the current window and restore saved; with exact, bytes left over are an error. */
        public void popLimit(long saved, boolean exact) {
            if (exact && remainingBits() > 0) {
                throw error(PbErrorKind.INVALID, remainingBits() + " bit(s) left over in a field that must fill its size");
            }
            pos = limit;
            limit = saved;
            windows--;
        }

        /** The next width bits (MSB first) as the low bits of a long. */
        public long readBits(int width) {
            need(width);
            load(pos >> 3, ((pos + width + 7) >> 3) - (pos >> 3));
            long v = 0;
            for (int left = width; left > 0;) {
                int b = data[(int) (pos >> 3)] & 0xff;
                int off = (int) (pos & 7);
                int take = Math.min(8 - off, left);
                v = (v << take) | ((b >> (8 - off - take)) & ((1 << take) - 1));
                pos += take;
                left -= take;
            }
            return v;
        }

        /** An nbytes-byte unsigned integer (its bit pattern, for 8 bytes). */
        public long readUint(int nbytes, boolean little) {
            need(nbytes * 8L);
            int start = (int) (pos >> 3);
            load(start, nbytes);
            long v = 0;
            for (int i = 0; i < nbytes; i++) {
                v = (v << 8) | (data[little ? start + nbytes - 1 - i : start + i] & 0xff);
            }
            pos += nbytes * 8L;
            return v;
        }

        public byte[] readBytes(long n) {
            need(n * 8);
            int start = (int) (pos >> 3);
            load(start, n);
            byte[] out = java.util.Arrays.copyOfRange(data, start, start + (int) n);
            pos += n * 8;
            return out;
        }

        /** The next n bytes as a read-only view of the input (zero-copy). */
        public java.nio.ByteBuffer readBuffer(long n) {
            need(n * 8);
            load(pos >> 3, n);
            java.nio.ByteBuffer view = Pb.view(data, (int) (pos >> 3), (int) n);
            pos += n * 8;
            return view;
        }

        /** readUntil as a read-only view of the input (zero-copy). */
        public java.nio.ByteBuffer readUntilBuffer(byte[] term, boolean optional) {
            int start = (int) (pos >> 3);
            int n = readUntil(term, optional).length;
            return Pb.view(data, start, n);
        }

        public void skipBits(long bits) {
            need(bits);
            pos += bits;
        }

        /** Bytes before a NUL terminator; the terminator is consumed. */
        public byte[] readCString() {
            int start = (int) (pos >> 3);
            int i = find(start, (int) (limit >> 3), NUL);
            if (i >= 0) {
                byte[] out = java.util.Arrays.copyOfRange(data, start, i);
                pos = (i + 1) * 8L;
                return out;
            }
            throw shortOf(remainingBits() + 8, "the NUL-terminated string");
        }

        /** Validate a decoded element count against the data that is left. */
        public int count(long n, long elemBits) {
            if (n < 0) {
                throw error(PbErrorKind.INVALID, "negative length " + n);
            }
            if (elemBits > 0 && n > remainingBits() / elemBits) {
                long bits = n > Long.MAX_VALUE / elemBits ? Long.MAX_VALUE : n * elemBits;
                throw shortOf(bits, "length " + n);
            }
            return (int) n;
        }

        public String utf8(byte[] raw, boolean untilNul) {
            int n = raw.length;
            if (untilNul) {
                for (int i = 0; i < raw.length; i++) {
                    if (raw[i] == 0) {
                        n = i;
                        break;
                    }
                }
            }
            try {
                return Pb.decodeText(0, raw, n);
            } catch (java.nio.charset.CharacterCodingException e) {
                throw error(PbErrorKind.TEXT, "invalid UTF-8");
            }
        }

        /** Text in encoding enc (see Pb.CHARSETS); padded cuts it at the first NUL character. */
        public String text(byte[] raw, int enc, boolean padded) {
            int n = raw.length;
            int unit = enc >= 3 ? 2 : 1;
            if (n % unit != 0) {
                throw error(PbErrorKind.TEXT, "invalid UTF-16 (an odd number of bytes)");
            }
            if (padded) {
                for (int i = 0; i < n; i += unit) {
                    if (raw[i] == 0 && raw[i + unit - 1] == 0) {
                        n = i;
                        break;
                    }
                }
            }
            try {
                return Pb.decodeText(enc, raw, n);
            } catch (java.nio.charset.CharacterCodingException e) {
                throw error(PbErrorKind.TEXT, "invalid " + Pb.ENCODING_NAMES[enc]);
            }
        }

        /**
         * One variable-length integer (kind: 0 uleb128, 1 sleb128, 2 zigzag,
         * 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.
         */
        public long readVarint(int kind) {
            if (kind == 5) {
                long first = readUint(1, false);
                return (first & 0x80) == 0 ? first : ((first & 0x7f) << 8) | readUint(1, false);
            }
            if (kind == 4) {
                long first = readUint(1, false);
                int n = 1 << (int) (first >>> 6);
                long q = first & 0x3f;
                if (n > 1) {
                    q = (q << (8 * (n - 1))) | readUint(n - 1, false);
                }
                return q;
            }
            long v = 0;
            int shift = 0;
            while (true) {
                long b = readUint(1, false);
                if (kind == 3) {
                    if (v >>> 57 != 0) {
                        throw error(PbErrorKind.INVALID, "the varint does not fit in 64 bits");
                    }
                    v = (v << 7) | (b & 0x7f);
                } else {
                    // The 10th byte holds bit 63 only (and, for sleb128, its sign).
                    boolean lastOk = kind == 1 ? (b & 0x7f) == 0 || (b & 0x7f) == 0x7f : (b & 0x7e) == 0;
                    if (shift >= 64 || (shift == 63 && ((b & 0x80) != 0 || !lastOk))) {
                        throw error(PbErrorKind.INVALID, "the varint does not fit in 64 bits");
                    }
                    v |= (b & 0x7f) << shift;
                }
                shift += 7;
                if ((b & 0x80) == 0) {
                    if (kind == 1 && shift < 64 && (b & 0x40) != 0) {
                        v |= -1L << shift;
                    }
                    break;
                }
            }
            if (kind == 2) {
                v = (v >>> 1) ^ -(v & 1);
            }
            return v;
        }

        /**
         * The bytes before term, consuming both. Without the terminator: the
         * rest of the input when optional, otherwise an error.
         */
        public byte[] readUntil(byte[] term, boolean optional) {
            int start = (int) (pos >> 3);
            int end = (int) (limit >> 3);
            int i = find(start, end, term);
            if (i >= 0) {
                byte[] found = java.util.Arrays.copyOfRange(data, start, i);
                pos = (long) (i + term.length) * 8;
                return found;
            }
            if (!optional) {
                throw shortOf(remainingBits() + 8, "the terminated field");
            }
            load(start, end - start);
            byte[] rest = java.util.Arrays.copyOfRange(data, start, end);
            pos = limit;
            return rest;
        }

        /**
         * Checksum algo of the input between two bit positions (whole bytes);
         * the bytes between holeFrom and holeTo count as zero. From a source
         * that cannot be read, the checksum of zeros (which then fails to match).
         */
        public long checksum(int algo, long from, long to, long holeFrom, long holeTo) {
            if (src != null) {
                long b = from / 8;
                long n = Math.max(to / 8 - b, 0);
                try {
                    src.load(b, n);
                } catch (Exception e) {
                    return Pb.checksum(algo, new byte[(int) n], 0, n, Math.max(holeFrom / 8 - b, 0),
                            Math.max(holeTo / 8 - b, 0));
                }
            }
            return Pb.checksum(algo, data, from / 8, to / 8, holeFrom / 8, holeTo / 8);
        }
    }

    /** Builds a byte buffer; integers may be written at any bit position. */
    public static final class PbWriter extends PbTrace {
        private record Placed(long at, byte[] data, String path) {}

        private byte[] buf = new byte[64];
        private int len;
        private long baseBits; // where buf goes in the output (sub writers)
        private final java.util.ArrayList<Placed> placed = new java.util.ArrayList<>();

        public byte[] toArray() {
            return java.util.Arrays.copyOf(buf, len);
        }

        private void add(int b) {
            if (len == buf.length) {
                buf = java.util.Arrays.copyOf(buf, buf.length * 2);
            }
            buf[len++] = (byte) b;
        }

        /**
         * A writer for a packet placed offset bytes after bit from of this
         * writer (the packet start), or after the start of the output (root).
         */
        public PbWriter sub(long from, long offset, boolean root) {
            long start = root ? 0 : baseBits + from;
            if (offset < 0 || start % 8 != 0) {
                throw error(PbErrorKind.RANGE, "bad offset " + offset + " (from bit " + start + ")");
            }
            PbWriter s = new PbWriter();
            s.baseBits = start + offset * 8;
            s.copyFrames(this);
            return s;
        }

        /** Keep what s wrote, for finish. */
        public void place(PbWriter s) {
            placed.add(new Placed(s.baseBits / 8, s.toArray(), path()));
            placed.addAll(s.placed);
        }

        /**
         * The output, with every placed packet written at its offset: past the
         * end (zero-filling the gap), or over bytes that must already match.
         */
        public byte[] finish() {
            placed.sort(java.util.Comparator.comparingLong(Placed::at));
            for (Placed p : placed) {
                // The output reaches the offset even when the packet is empty.
                while (len < p.at()) {
                    add(0);
                }
                for (int i = 0; i < p.data().length; i++) {
                    long k = p.at() + i;
                    if (k < len) {
                        if (buf[(int) k] != p.data()[i]) {
                            throw new PbException(PbErrorKind.MISMATCH, "the packet placed at byte " + p.at()
                                    + " does not match the bytes already there", p.path(), k * 8, 0);
                        }
                    } else {
                        add(p.data()[i]);
                    }
                }
            }
            placed.clear();
            return toArray();
        }

        /** The low width bits of value, MSB first. */
        public void writeBits(long value, int width) {
            for (int left = width; left > 0;) {
                if ((pos & 7) == 0) {
                    add(0);
                }
                int off = (int) (pos & 7);
                int take = Math.min(8 - off, left);
                int bits = (int) ((value >>> (left - take)) & ((1 << take) - 1));
                buf[len - 1] |= (byte) (bits << (8 - off - take));
                pos += take;
                left -= take;
            }
        }

        /** The low nbytes bytes of value. */
        public void writeUint(long value, int nbytes, boolean little) {
            for (int i = 0; i < nbytes; i++) {
                int shift = little ? 8 * i : 8 * (nbytes - 1 - i);
                add((int) (value >>> shift));
            }
            pos += nbytes * 8L;
        }

        public void writeBytes(byte[] bytes) {
            for (byte b : bytes) {
                add(b);
            }
            pos += bytes.length * 8L;
        }

        /** The bytes between the buffer's position and limit. */
        public void writeBytes(java.nio.ByteBuffer bytes) {
            writeBytes(Pb.bytes(bytes));
        }

        public void writeZeroBits(long bits) {
            for (; bits > 32; bits -= 32) {
                writeBits(0, 32);
            }
            if (bits > 0) {
                writeBits(0, (int) bits);
            }
        }

        /**
         * End a window of size bytes that started at bit start: the content must
         * fit (and fill it when exact); the rest is zero-filled.
         */
        public void endWindow(long start, long size, boolean exact) {
            long used = pos - start;
            if (size < 0 || used > size * 8) {
                throw error(PbErrorKind.RANGE, "the content takes " + used + " bit(s), more than its size of "
                        + size + " byte(s)");
            }
            if (exact && used != size * 8) {
                throw error(PbErrorKind.MISMATCH, "the content takes " + used + " bit(s) but must fill its "
                        + size + " byte(s)");
            }
            writeZeroBits(size * 8 - used);
        }

        /** Overwrite nbytes bytes at bit position at (byte aligned). */
        public void patchUint(long at, long value, int nbytes, boolean little) {
            for (int i = 0; i < nbytes; i++) {
                int shift = little ? 8 * i : 8 * (nbytes - 1 - i);
                buf[(int) (at / 8) + i] = (byte) (value >>> shift);
            }
        }

        /** Overwrite width bits at bit position at, MSB first. */
        public void patchBits(long at, long value, int width) {
            for (int i = 0; i < width; i++) {
                int bit = (int) ((value >>> (width - 1 - i)) & 1);
                int b = (int) ((at + i) / 8);
                int off = 7 - (int) ((at + i) % 8);
                buf[b] = (byte) ((buf[b] & ~(1 << off)) | (bit << off));
            }
        }

        /**
         * Checksum algo of the output between two bit positions (whole bytes);
         * the bytes between holeFrom and holeTo count as zero.
         */
        public long checksum(int algo, long from, long to, long holeFrom, long holeTo) {
            return Pb.checksum(algo, buf, from / 8, to / 8, holeFrom / 8, holeTo / 8);
        }

        public byte[] utf8Bytes(String s) {
            try {
                return Pb.encodeText(0, s);
            } catch (java.nio.charset.CharacterCodingException e) {
                throw error(PbErrorKind.TEXT, "the string is not valid Unicode (unpaired surrogate)");
            }
        }

        /** s in encoding enc (see Pb.CHARSETS). */
        public byte[] textBytes(String s, int enc) {
            try {
                return Pb.encodeText(enc, s);
            } catch (java.nio.charset.CharacterCodingException e) {
                throw error(PbErrorKind.TEXT, "the string is not valid " + Pb.ENCODING_NAMES[enc]);
            }
        }

        /** One variable-length integer (see PbReader.readVarint). */
        public void writeVarint(int kind, long v) {
            switch (kind) {
                case 5:
                    if (Long.compareUnsigned(v, 0x80) < 0) {
                        writeUint(v, 1, false);
                    } else if (Long.compareUnsigned(v, 0x7fff) <= 0) {
                        writeUint(v | 0x8000, 2, false);
                    } else {
                        throw error(PbErrorKind.RANGE, Long.toUnsignedString(v) + " does not fit in a varint15");
                    }
                    return;
                case 4:
                    if (Long.compareUnsigned(v, 0x3f) <= 0) {
                        writeUint(v, 1, false);
                    } else if (Long.compareUnsigned(v, 0x3fff) <= 0) {
                        writeUint(v | (1L << 14), 2, false);
                    } else if (Long.compareUnsigned(v, 0x3fffffffL) <= 0) {
                        writeUint(v | (2L << 30), 4, false);
                    } else if (Long.compareUnsigned(v, 0x3fffffffffffffffL) <= 0) {
                        writeUint(v | (3L << 62), 8, false);
                    } else {
                        throw error(PbErrorKind.RANGE, Long.toUnsignedString(v) + " does not fit in a QUIC varint");
                    }
                    return;
                case 1: {
                    long x = v;
                    while (true) {
                        long b = x & 0x7f;
                        x >>= 7;
                        boolean done = (x == 0 && (b & 0x40) == 0) || (x == -1 && (b & 0x40) != 0);
                        writeUint(done ? b : b | 0x80, 1, false);
                        if (done) {
                            return;
                        }
                    }
                }
                case 3: {
                    long[] groups = new long[10];
                    int n = 0;
                    groups[n++] = v & 0x7f;
                    for (v >>>= 7; v != 0; v >>>= 7) {
                        groups[n++] = (v & 0x7f) | 0x80;
                    }
                    for (int i = n - 1; i >= 0; i--) {
                        writeUint(groups[i], 1, false);
                    }
                    return;
                }
                default:
                    if (kind == 2) {
                        v = (v << 1) ^ (v >> 63);
                    }
                    while (true) {
                        long b = v & 0x7f;
                        v >>>= 7;
                        writeUint(v != 0 ? b | 0x80 : b, 1, false);
                        if (v == 0) {
                            return;
                        }
                    }
            }
        }

        public void checkNoTerm(java.nio.ByteBuffer data, byte[] term) {
            checkNoTerm(Pb.bytes(data), term);
        }

        public void checkNoTerm(byte[] data, byte[] term) {
            for (int i = 0; i + term.length <= data.length; i++) {
                boolean hit = true;
                for (int k = 0; k < term.length && hit; k++) {
                    hit = data[i + k] == term[k];
                }
                if (hit) {
                    throw error(PbErrorKind.INVALID, "the value contains its terminator");
                }
            }
        }

        public void checkFits(long length, long size) {
            if (length > size) {
                throw error(PbErrorKind.RANGE, length + " byte(s) do not fit in " + size);
            }
        }

        public void checkNoNul(byte[] data) {
            for (byte b : data) {
                if (b == 0) {
                    throw error(PbErrorKind.TEXT, "the string contains a NUL byte");
                }
            }
        }

        public void checkLen(long actual, long expected) {
            if (actual != expected) {
                throw error(PbErrorKind.MISMATCH, actual + " element(s) but the length expression says " + expected);
            }
        }

        /** v (the bit pattern of an unsigned value) must fit in width bits. */
        public void checkU(long v, int width) {
            if (width < 64 && (v >>> width) != 0) {
                throw error(PbErrorKind.RANGE, "value " + v + " does not fit in " + width + " bit(s)");
            }
        }

        public void checkI(long v, int width) {
            if (width < 64 && (v < -(1L << (width - 1)) || v > (1L << (width - 1)) - 1)) {
                throw error(PbErrorKind.RANGE, "value " + v + " does not fit in " + width + " signed bit(s)");
            }
        }
    }

    /** Helpers the generated code calls. */
    static final class Pb {
        private Pb() {}

        /** Text encodings by id: UTF-8, ASCII, Latin-1, UTF-16LE, UTF-16BE (all strict). */
        static final java.nio.charset.Charset[] CHARSETS = {
            java.nio.charset.StandardCharsets.UTF_8,
            java.nio.charset.StandardCharsets.US_ASCII,
            java.nio.charset.StandardCharsets.ISO_8859_1,
            java.nio.charset.StandardCharsets.UTF_16LE,
            java.nio.charset.StandardCharsets.UTF_16BE,
        };

        static final String[] ENCODING_NAMES = {"UTF-8", "ASCII", "Latin-1", "UTF-16", "UTF-16"};

        static String decodeText(int enc, byte[] raw, int n) throws java.nio.charset.CharacterCodingException {
            return CHARSETS[enc].newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(raw, 0, n))
                    .toString();
        }

        static byte[] encodeText(int enc, String s) throws java.nio.charset.CharacterCodingException {
            java.nio.ByteBuffer b = CHARSETS[enc].newEncoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .encode(java.nio.CharBuffer.wrap(s));
            return bytes(b);
        }

        /** A read-only view of data[offset, offset + n), positioned at 0. */
        static java.nio.ByteBuffer view(byte[] data, int offset, int n) {
            return java.nio.ByteBuffer.wrap(data, offset, n).slice().asReadOnlyBuffer();
        }

        /** A copy of the bytes between the buffer's position and limit. */
        static byte[] bytes(java.nio.ByteBuffer b) {
            byte[] out = new byte[b.remaining()];
            b.duplicate().get(out);
            return out;
        }

        /** The byte length of s in UTF-8. */
        static int utf8Len(String s) {
            int n = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c < 0x80) {
                    n += 1;
                } else if (c < 0x800) {
                    n += 2;
                } else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                    n += 4;
                    i++;
                } else {
                    n += 3;
                }
            }
            return n;
        }

        private static final char[] HEX = "0123456789abcdef".toCharArray();

        /** Bytes as a JSON string of hex digits (for toJson). */
        static String jsonHex(byte[] b) {
            StringBuilder sb = new StringBuilder(b.length * 2 + 2).append('"');
            for (byte x : b) {
                sb.append(HEX[(x >> 4) & 15]).append(HEX[x & 15]);
            }
            return sb.append('"').toString();
        }

        static String jsonHex(java.nio.ByteBuffer b) {
            return jsonHex(bytes(b));
        }

        /** A JSON string literal (for toJson). */
        static String jsonStr(String s) {
            StringBuilder sb = new StringBuilder("\"");
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"') {
                    sb.append("\\\"");
                } else if (c == '\\') {
                    sb.append("\\\\");
                } else if (c < 0x20) {
                    sb.append(String.format("\\u%04x", (int) c));
                } else {
                    sb.append(c);
                }
            }
            return sb.append('"').toString();
        }

        // CRC parameters by algorithm number: width, polynomial (reflected for
        // reflected CRCs), initial value, reflected (1), final XOR.
        private static final long[][] CRC = {
            {8, 0x07, 0, 0, 0}, // crc8 (CRC-8/SMBUS)
            {16, 0xA001, 0, 1, 0}, // crc16_arc
            {16, 0x1021, 0xFFFF, 0, 0}, // crc16_ccitt_false (CRC-16/IBM-3740)
            {16, 0x1021, 0, 0, 0}, // crc16_xmodem
            {16, 0x8408, 0, 1, 0}, // crc16_kermit
            {16, 0xA001, 0xFFFF, 1, 0}, // crc16_modbus
            {32, 0xEDB88320L, 0xFFFFFFFFL, 1, 0xFFFFFFFFL}, // crc32 (CRC-32/ISO-HDLC)
            {32, 0x82F63B78L, 0xFFFFFFFFL, 1, 0xFFFFFFFFL}, // crc32c (CRC-32/ISCSI)
        };

        /**
         * Checksum algo of buf[from..to) with buf[holeFrom..holeTo) as zeros.
         * 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8,
         * 12: sum16, 13: sum32_fold16.
         */
        static long checksum(int algo, byte[] buf, long from, long to, long holeFrom, long holeTo) {
            if (algo < 8) {
                long[] p = CRC[algo];
                int width = (int) p[0];
                long poly = p[1];
                long mask = (1L << width) - 1;
                long crc = p[2];
                for (long i = from; i < to; i++) {
                    long x = i >= holeFrom && i < holeTo ? 0 : buf[(int) i] & 0xff;
                    if (p[3] == 1) {
                        crc ^= x;
                        for (int k = 0; k < 8; k++) {
                            crc = (crc & 1) != 0 ? (crc >>> 1) ^ poly : crc >>> 1;
                        }
                    } else {
                        crc ^= x << (width - 8);
                        for (int k = 0; k < 8; k++) {
                            crc = ((crc & (1L << (width - 1))) != 0 ? (crc << 1) ^ poly : crc << 1) & mask;
                        }
                    }
                }
                return (crc ^ p[4]) & mask;
            }
            long a = 0;
            long b = 0;
            for (long i = from; i < to; i++) {
                long x = i >= holeFrom && i < holeTo ? 0 : buf[(int) i] & 0xff;
                switch (algo) {
                    case 8:
                        a += (i - from) % 2 == 0 ? x << 8 : x;
                        break;
                    case 9:
                        a = (a + x) % 255;
                        b = (b + a) % 255;
                        break;
                    case 10:
                        a = (a + x) & 0xFF;
                        break;
                    case 12:
                        a = (a + x) & 0xFFFF;
                        break;
                    case 13:
                        a = (a + (x << (int) (8 * (3 - (i - from) % 4)))) & 0xFFFFFFFFL;
                        break;
                    default:
                        a ^= x;
                        break;
                }
            }
            if (algo == 8) {
                while ((a >>> 16) != 0) {
                    a = (a & 0xFFFF) + (a >>> 16);
                }
                return ~a & 0xFFFF;
            }
            if (algo == 13) {
                return ((a >>> 16) + (a & 0xFFFF)) & 0xFFFF;
            }
            return algo == 9 ? (b << 8) | a : a;
        }

        /** Padding needed after offset bits to reach a multiple of unit bits. */
        static long pad(long offset, long unit) {
            return (unit - offset % unit) % unit;
        }

        /** The low width bits of v, sign-extended. */
        static long sext(long v, int width) {
            if (width < 64 && ((v >>> (width - 1)) & 1) == 1) {
                v |= -1L << width;
            }
            return v;
        }

        /** v cut to width bits, as a signed or unsigned value. */
        static long trunc(long v, int width, boolean signed) {
            if (width >= 64) {
                return v;
            }
            long u = v & ((1L << width) - 1);
            return signed ? sext(u, width) : u;
        }

        static long div(long a, long b) {
            if (b == 0) {
                return 0;
            }
            if (b == -1) {
                return -a;
            }
            return a / b;
        }

        static long mod(long a, long b) {
            if (b == 0 || b == -1) {
                return 0;
            }
            return a % b;
        }

        static long shl(long a, long b) {
            return b < 0 || b > 63 ? 0 : a << b;
        }

        static long shr(long a, long b) {
            return b < 0 ? 0 : a >> Math.min(b, 63);
        }

        static long pow(long b, long e) {
            if (e < 0) {
                return 0;
            }
            long acc = 1;
            for (long x = e; x != 0; x >>>= 1) {
                if ((x & 1) == 1) {
                    acc *= b;
                }
                b *= b;
            }
            return acc;
        }

        /** A double as an integer: truncated, saturating, NaN as 0. */
        static long ftoi(double v) {
            return (long) v;
        }

        /** An unsigned 64-bit value (its bit pattern) as a double. */
        static double u64ToDouble(long v) {
            return v >= 0 ? (double) v : ((double) (v >>> 1)) * 2.0 + (v & 1);
        }

        // Element i of an array, 0 when out of range; U8 for byte buffers.
        static long atU8(byte[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] & 0xff : 0;
        }

        static long atU8(java.nio.ByteBuffer a, long i) {
            return i >= 0 && i < a.remaining() ? a.get(a.position() + (int) i) & 0xff : 0;
        }

        static long at(byte[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] : 0;
        }

        static long at(short[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] : 0;
        }

        static long at(int[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] : 0;
        }

        static long at(long[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] : 0;
        }

        static double at(float[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] : 0;
        }

        static double at(double[] a, long i) {
            return i >= 0 && i < a.length ? a[(int) i] : 0;
        }

        /** The length of a byte buffer: an array, or (zero-copy) the bytes between position and limit. */
        static int len(byte[] a) {
            return a.length;
        }

        static int len(java.nio.ByteBuffer a) {
            return a.remaining();
        }

        // Sums and products of array elements (wrapping), as long or double.
        static long sumU8(byte[] a) {
            long s = 0;
            for (byte x : a) {
                s += x & 0xff;
            }
            return s;
        }

        static long sumU8(java.nio.ByteBuffer a) {
            return sumU8(bytes(a));
        }

        static long productU8(byte[] a) {
            long s = 1;
            for (byte x : a) {
                s *= x & 0xff;
            }
            return s;
        }

        static long productU8(java.nio.ByteBuffer a) {
            return productU8(bytes(a));
        }

        static long sum(byte[] a) {
            long s = 0;
            for (byte x : a) {
                s += x;
            }
            return s;
        }

        static long sum(short[] a) {
            long s = 0;
            for (short x : a) {
                s += x;
            }
            return s;
        }

        static long sum(int[] a) {
            long s = 0;
            for (int x : a) {
                s += x;
            }
            return s;
        }

        static long sum(long[] a) {
            long s = 0;
            for (long x : a) {
                s += x;
            }
            return s;
        }

        static double sum(float[] a) {
            double s = 0;
            for (float x : a) {
                s += x;
            }
            return s;
        }

        static double sum(double[] a) {
            double s = 0;
            for (double x : a) {
                s += x;
            }
            return s;
        }

        static long product(byte[] a) {
            long s = 1;
            for (byte x : a) {
                s *= x;
            }
            return s;
        }

        static long product(short[] a) {
            long s = 1;
            for (short x : a) {
                s *= x;
            }
            return s;
        }

        static long product(int[] a) {
            long s = 1;
            for (int x : a) {
                s *= x;
            }
            return s;
        }

        static long product(long[] a) {
            long s = 1;
            for (long x : a) {
                s *= x;
            }
            return s;
        }

        static double product(float[] a) {
            double s = 1;
            for (float x : a) {
                s *= x;
            }
            return s;
        }

        static double product(double[] a) {
            double s = 1;
            for (double x : a) {
                s *= x;
            }
            return s;
        }
    }

    // ---- generated packets --------------------------------------------------
