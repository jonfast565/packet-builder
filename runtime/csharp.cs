    // ---- packet-builder runtime ---------------------------------------------

    /// <summary>What went wrong while decoding or encoding.</summary>
    public enum PbErrorKind
    {
        /// <summary>The input ended before the packet did; NeededBits more would help.</summary>
        Incomplete,
        /// <summary>Malformed data: a bad length, nesting too deep, ...</summary>
        Invalid,
        /// <summary>A value does not fit in its field.</summary>
        Range,
        /// <summary>A string is not valid text, or contains a NUL where none is allowed.</summary>
        Text,
        /// <summary>A length, derived field or checksum does not match the data.</summary>
        Mismatch,
        /// <summary>A value breaks a declared constraint.</summary>
        Constraint,
    }

    /// <summary>Decoding from a buffer that may not hold the whole packet yet (a stream):
    /// the value and the bytes it took, or how many more bytes are needed at least.</summary>
    public sealed class PbStatus<T>
    {
        public bool IsDone { get; private set; }
        public T Value { get; private set; } = default!;
        public int Consumed { get; private set; }
        public int Needed { get; private set; }

        public static PbStatus<T> Done(T value, int consumed) => new PbStatus<T> { IsDone = true, Value = value, Consumed = consumed };
        public static PbStatus<T> Incomplete(int needed) => new PbStatus<T> { Needed = needed };
    }

    /// <summary>Thrown when data cannot be decoded or a value cannot be encoded.</summary>
    public sealed class PbException : Exception
    {
        public PbErrorKind Kind { get; }
        /// <summary>Where it happened: Packet.field[index].field.</summary>
        public string Path { get; }
        public long BitOffset { get; }
        /// <summary>For Incomplete: the least number of extra input bits needed.</summary>
        public long NeededBits { get; }
        public string Reason { get; }

        public PbException(PbErrorKind kind, string reason, string path, long bitOffset, long neededBits = 0)
            : base((path.Length > 0 ? path + ": " : "") + reason + $" (at bit {bitOffset})")
        {
            Kind = kind;
            Reason = reason;
            Path = path;
            BitOffset = bitOffset;
            NeededBits = neededBits;
        }
    }

    /// <summary>The packets being decoded or encoded, innermost last, each with
    /// the field it is working on: the path reported in errors.</summary>
    public abstract class PbTrace
    {
        /// <summary>The deepest packet nesting accepted.</summary>
        public const int MaxDepth = 64;

        private readonly List<(string Packet, string Field, long Index)> frames = new List<(string, string, long)>();
        protected long pos; // in bits

        public long PositionBits => pos;

        public void Enter(string packet)
        {
            frames.Add((packet, "", -1));
            if (frames.Count > MaxDepth) throw Error(PbErrorKind.Invalid, $"packets nested more than {MaxDepth} deep");
        }

        public void Leave() => frames.RemoveAt(frames.Count - 1);

        /// <summary>Start from the frames (and version) of <paramref name="other"/> (for sub writers).</summary>
        protected void CopyFrames(PbTrace other)
        {
            frames.AddRange(other.frames);
            version = other.version;
        }

        private int version; // protocol version; 0 until set

        // @versions{
        /// <summary>The protocol version (<c>version</c>), or <paramref name="latest"/> while none is set.</summary>
        public long VersionOr(int latest) => version == 0 ? latest : version;

        /// <summary>Code as protocol version <paramref name="v"/>, which must be in min..latest.</summary>
        public void SetVersion(long v, int min, int latest)
        {
            if (v < min || v > latest) throw Error(PbErrorKind.Constraint, $"version {v} is not one of the versions {min}..{latest}");
            version = (int)v;
        }

        /// <summary>The version a value carries in-band: used unless one is set already.</summary>
        public void AdoptVersion(long v, int min, int latest)
        {
            if (version == 0) SetVersion(v, min, latest);
        }
        // @versions}

        public void At(string field) => frames[frames.Count - 1] = (frames[frames.Count - 1].Packet, field, -1);

        public void AtIndex(long index)
        {
            var f = frames[frames.Count - 1];
            frames[frames.Count - 1] = (f.Packet, f.Field, index);
        }

        public string Path()
        {
            var sb = new System.Text.StringBuilder();
            if (frames.Count > 0) sb.Append(frames[0].Packet);
            foreach (var f in frames)
            {
                if (f.Field.Length == 0) break;
                sb.Append('.').Append(f.Field);
                if (f.Index >= 0) sb.Append('[').Append(f.Index).Append(']');
            }
            return sb.ToString();
        }

        public PbException Error(PbErrorKind kind, string reason, long neededBits = 0) =>
            new PbException(kind, reason, Path(), pos, neededBits);
    }

    /// <summary>Reads integers of any bit width (MSB-first) and byte-aligned values.</summary>
    public sealed class PbReader : PbTrace
    {
        private readonly byte[] data;
        private long limit; // end of the readable data in bits (a window inside data)
        private int windows; // windows open

        public PbReader(byte[] data)
        {
            this.data = data;
            limit = (long)data.Length * 8;
        }

        public long RemainingBits => limit - pos;
        /// <summary>Whole bytes left before the end of the window or input (`remaining`).</summary>
        public long RemainingBytes => (limit - pos) / 8;

        /// <summary>Read from <paramref name="offset"/> bytes after bit <paramref name="from"/>
        /// (the packet start, or 0 for the start of the input) until JumpBack;
        /// windows do not apply there.</summary>
        public (long, long, int) Jump(long from, long offset)
        {
            if (offset < 0 || from % 8 != 0 || offset > data.Length || from + offset * 8 > (long)data.Length * 8)
                throw Error(PbErrorKind.Invalid, $"offset {offset} is past the end of the input");
            var saved = (pos, limit, windows);
            pos = from + offset * 8;
            limit = (long)data.Length * 8;
            windows = 0;
            return saved;
        }

        /// <summary>Return to where Jump left.</summary>
        public void JumpBack((long, long, int) saved) => (pos, limit, windows) = saved;

        /// <summary>bits more bits are needed than are left: incomplete input at
        /// the top level, invalid data inside a window.</summary>
        private PbException Short(long bits, string what)
        {
            if (windows == 0)
                return Error(PbErrorKind.Incomplete,
                    $"unexpected end of data: {what} needs {bits} more bit(s), {RemainingBits} left", bits - RemainingBits);
            return Error(PbErrorKind.Invalid, $"{what} needs {bits} bit(s) but its window has {RemainingBits} left");
        }

        private void Need(long bits)
        {
            if (bits < 0 || bits > RemainingBits) throw Short(bits, "the field");
        }

        /// <summary>Restrict reading to the next n bytes; returns the previous limit.</summary>
        public long PushLimit(long n)
        {
            if (n < 0) throw Error(PbErrorKind.Invalid, $"negative size {n}");
            if (n > RemainingBits / 8) throw Short(n * 8, "the window");
            long saved = limit;
            limit = pos + n * 8;
            windows++;
            return saved;
        }

        /// <summary>Skip what is left of the current window and restore saved;
        /// with exact, bytes left over are an error.</summary>
        public void PopLimit(long saved, bool exact)
        {
            if (exact && RemainingBits > 0)
                throw Error(PbErrorKind.Invalid, $"{RemainingBits} bit(s) left over in a field that must fill its size");
            pos = limit;
            limit = saved;
            windows--;
        }

        public ulong ReadBits(int width)
        {
            Need(width);
            ulong v = 0;
            for (int left = width; left > 0;)
            {
                int b = data[pos >> 3];
                int off = (int)(pos & 7);
                int take = Math.Min(8 - off, left);
                v = (v << take) | (uint)((b >> (8 - off - take)) & ((1 << take) - 1));
                pos += take;
                left -= take;
            }
            return v;
        }

        public ulong ReadUint(int nbytes, bool little)
        {
            Need(nbytes * 8L);
            long start = pos >> 3;
            ulong v = 0;
            for (int i = 0; i < nbytes; i++)
                v = (v << 8) | data[little ? start + nbytes - 1 - i : start + i];
            pos += nbytes * 8L;
            return v;
        }

        public byte[] ReadBytes(long n)
        {
            Need(n * 8);
            var outp = new byte[n];
            Array.Copy(data, pos >> 3, outp, 0, n);
            pos += n * 8;
            return outp;
        }

        /// <summary>The next n bytes as a view of the input (zero-copy).</summary>
        public ReadOnlyMemory<byte> ReadMemory(long n)
        {
            Need(n * 8);
            var view = new ReadOnlyMemory<byte>(data, (int)(pos >> 3), (int)n);
            pos += n * 8;
            return view;
        }

        /// <summary>ReadUntil as a view of the input (zero-copy).</summary>
        public ReadOnlyMemory<byte> ReadUntilMemory(byte[] term, bool optional)
        {
            long start = pos >> 3;
            int n = ReadUntil(term, optional).Length;
            return new ReadOnlyMemory<byte>(data, (int)start, n);
        }

        public void SkipBits(long bits)
        {
            Need(bits);
            pos += bits;
        }

        /// <summary>Bytes before a NUL terminator; the terminator is consumed.</summary>
        public byte[] ReadCString()
        {
            long start = pos >> 3;
            int end = Array.IndexOf(data, (byte)0, (int)start, (int)((limit >> 3) - start));
            if (end < 0) throw Short(RemainingBits + 8, "the NUL-terminated string");
            var outp = new byte[end - start];
            Array.Copy(data, start, outp, 0, outp.Length);
            pos = (end + 1) * 8L;
            return outp;
        }

        /// <summary>Validate a decoded element count against the data that is left.</summary>
        public int Count(long n, long elemBits)
        {
            if (n < 0) throw Error(PbErrorKind.Invalid, $"negative length {n}");
            if (elemBits > 0 && n > RemainingBits / elemBits)
            {
                long bits = n > long.MaxValue / elemBits ? long.MaxValue : n * elemBits;
                throw Short(bits, $"length {n}");
            }
            return (int)n;
        }

        public string Utf8(byte[] raw, bool untilNul)
        {
            int n = raw.Length;
            if (untilNul)
            {
                int nul = Array.IndexOf(raw, (byte)0);
                if (nul >= 0) n = nul;
            }
            try { return Pb.StrictUtf8.GetString(raw, 0, n); }
            catch (ArgumentException) { throw Error(PbErrorKind.Text, "invalid UTF-8"); }
        }

        /// <summary>Text in encoding enc (see Pb.Encodings); padded cuts it at the
        /// first NUL character.</summary>
        public string Text(byte[] raw, int enc, bool padded)
        {
            int n = raw.Length, unit = enc >= 3 ? 2 : 1;
            if (n % unit != 0) throw Error(PbErrorKind.Text, "invalid UTF-16 (an odd number of bytes)");
            if (padded)
            {
                for (int i = 0; i < n; i += unit)
                {
                    if (raw[i] == 0 && raw[i + unit - 1] == 0) { n = i; break; }
                }
            }
            try { return Pb.Encodings[enc].GetString(raw, 0, n); }
            catch (ArgumentException) { throw Error(PbErrorKind.Text, $"invalid {Pb.EncodingNames[enc]}"); }
        }

        /// <summary>One variable-length integer (kind: 0 uleb128, 1 sleb128,
        /// 2 zigzag, 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.</summary>
        public ulong ReadVarint(int kind)
        {
            if (kind == 5)
            {
                ulong first = ReadUint(1, false);
                return (first & 0x80) == 0 ? first : ((first & 0x7f) << 8) | ReadUint(1, false);
            }
            if (kind == 4)
            {
                ulong first = ReadUint(1, false);
                int n = 1 << (int)(first >> 6);
                ulong q = first & 0x3f;
                if (n > 1) q = (q << (8 * (n - 1))) | ReadUint(n - 1, false);
                return q;
            }
            ulong v = 0;
            int shift = 0;
            while (true)
            {
                ulong b = ReadUint(1, false);
                if (kind == 3)
                {
                    if (v >> 57 != 0) throw Error(PbErrorKind.Invalid, "the varint does not fit in 64 bits");
                    v = (v << 7) | (b & 0x7f);
                }
                else
                {
                    // The 10th byte holds bit 63 only (and, for sleb128, its sign).
                    bool lastOk = kind == 1 ? (b & 0x7f) == 0 || (b & 0x7f) == 0x7f : (b & 0x7e) == 0;
                    if (shift >= 64 || (shift == 63 && ((b & 0x80) != 0 || !lastOk)))
                        throw Error(PbErrorKind.Invalid, "the varint does not fit in 64 bits");
                    v |= (b & 0x7f) << shift;
                }
                shift += 7;
                if ((b & 0x80) == 0)
                {
                    if (kind == 1 && shift < 64 && (b & 0x40) != 0) v |= ulong.MaxValue << shift;
                    break;
                }
            }
            if (kind == 2) v = (v >> 1) ^ unchecked(0UL - (v & 1));
            return v;
        }

        /// <summary>The bytes before term, consuming both. Without the terminator:
        /// the rest of the input when optional, otherwise an error.</summary>
        public byte[] ReadUntil(byte[] term, bool optional)
        {
            long start = pos >> 3, end = limit >> 3;
            for (long i = start; i + term.Length <= end; i++)
            {
                bool hit = true;
                for (int k = 0; k < term.Length && hit; k++) hit = data[i + k] == term[k];
                if (!hit) continue;
                var found = new byte[i - start];
                Array.Copy(data, start, found, 0, found.Length);
                pos = (i + term.Length) * 8;
                return found;
            }
            if (!optional) throw Short(RemainingBits + 8, "the terminated field");
            var rest = new byte[end - start];
            Array.Copy(data, start, rest, 0, rest.Length);
            pos = limit;
            return rest;
        }

        /// <summary>Checksum algo of the input between two bit positions (whole
        /// bytes); the bytes between holeFrom and holeTo count as zero.</summary>
        public ulong Checksum(int algo, long from, long to, long holeFrom, long holeTo) =>
            Pb.Checksum(algo, data, from / 8, to / 8, holeFrom / 8, holeTo / 8);
    }

    /// <summary>Builds a byte buffer; integers may be written at any bit position.</summary>
    public sealed class PbWriter : PbTrace
    {
        private readonly List<byte> buf = new List<byte>();
        private long baseBits; // where buf goes in the output (sub writers)
        private readonly List<(long At, byte[] Data, string Path)> placed = new List<(long, byte[], string)>();

        public byte[] ToArray() => buf.ToArray();

        /// <summary>A writer for a packet placed <paramref name="offset"/> bytes after bit
        /// <paramref name="from"/> of this writer (the packet start), or after the start of
        /// the output (<paramref name="root"/>).</summary>
        public PbWriter Sub(long from, long offset, bool root)
        {
            long start = root ? 0 : baseBits + from;
            if (offset < 0 || start % 8 != 0) throw Error(PbErrorKind.Range, $"bad offset {offset} (from bit {start})");
            var s = new PbWriter { baseBits = start + offset * 8 };
            s.CopyFrames(this);
            return s;
        }

        /// <summary>Keep what <paramref name="s"/> wrote, for Finish.</summary>
        public void Place(PbWriter s)
        {
            placed.Add((s.baseBits / 8, s.buf.ToArray(), Path()));
            placed.AddRange(s.placed);
        }

        /// <summary>The output, with every placed packet written at its offset: past
        /// the end (zero-filling the gap), or over bytes that must already match.</summary>
        public byte[] Finish()
        {
            foreach (var (at, data, path) in placed.OrderBy(p => p.At))
            {
                // The output reaches the offset even when the packet is empty.
                while (buf.Count < at) buf.Add(0);
                for (int i = 0; i < data.Length; i++)
                {
                    long k = at + i;
                    if (k < buf.Count)
                    {
                        if (buf[(int)k] != data[i])
                            throw new PbException(PbErrorKind.Mismatch,
                                $"the packet placed at byte {at} does not match the bytes already there", path, k * 8);
                    }
                    else
                    {
                        while (buf.Count < k) buf.Add(0);
                        buf.Add(data[i]);
                    }
                }
            }
            placed.Clear();
            return buf.ToArray();
        }

        public void WriteBits(ulong value, int width)
        {
            for (int left = width; left > 0;)
            {
                if ((pos & 7) == 0) buf.Add(0);
                int off = (int)(pos & 7);
                int take = Math.Min(8 - off, left);
                int bits = (int)((value >> (left - take)) & (ulong)((1 << take) - 1));
                buf[buf.Count - 1] |= (byte)(bits << (8 - off - take));
                pos += take;
                left -= take;
            }
        }

        public void WriteUint(ulong value, int nbytes, bool little)
        {
            for (int i = 0; i < nbytes; i++)
            {
                int shift = little ? 8 * i : 8 * (nbytes - 1 - i);
                buf.Add((byte)(value >> shift));
            }
            pos += nbytes * 8L;
        }

        public void WriteBytes(byte[] bytes)
        {
            buf.AddRange(bytes);
            pos += bytes.Length * 8L;
        }

        public void WriteBytes(ReadOnlyMemory<byte> bytes) => WriteBytes(bytes.ToArray());

        public void WriteZeroBits(long bits)
        {
            for (; bits > 32; bits -= 32) WriteBits(0, 32);
            if (bits > 0) WriteBits(0, (int)bits);
        }

        /// <summary>End a window of size bytes that started at bit start: the
        /// content must fit (and fill it when exact); the rest is zero-filled.</summary>
        public void EndWindow(long start, long size, bool exact)
        {
            long used = pos - start;
            if (size < 0 || used > size * 8)
                throw Error(PbErrorKind.Range, $"the content takes {used} bit(s), more than its size of {size} byte(s)");
            if (exact && used != size * 8)
                throw Error(PbErrorKind.Mismatch, $"the content takes {used} bit(s) but must fill its {size} byte(s)");
            WriteZeroBits(size * 8 - used);
        }

        /// <summary>Overwrite nbytes bytes at bit position at (byte aligned).</summary>
        public void PatchUint(long at, ulong value, int nbytes, bool little)
        {
            for (int i = 0; i < nbytes; i++)
            {
                int shift = little ? 8 * i : 8 * (nbytes - 1 - i);
                buf[(int)(at / 8) + i] = (byte)(value >> shift);
            }
        }

        /// <summary>Overwrite width bits at bit position at, MSB first.</summary>
        public void PatchBits(long at, ulong value, int width)
        {
            for (int i = 0; i < width; i++)
            {
                int bit = (int)((value >> (width - 1 - i)) & 1);
                int b = (int)((at + i) / 8);
                int off = 7 - (int)((at + i) % 8);
                buf[b] = (byte)((buf[b] & ~(1 << off)) | (bit << off));
            }
        }

        /// <summary>Checksum algo of the output between two bit positions (whole
        /// bytes); the bytes between holeFrom and holeTo count as zero.</summary>
        public ulong Checksum(int algo, long from, long to, long holeFrom, long holeTo) =>
            Pb.Checksum(algo, buf.ToArray(), from / 8, to / 8, holeFrom / 8, holeTo / 8);

        public byte[] Utf8Bytes(string s)
        {
            try { return Pb.StrictUtf8.GetBytes(s); }
            catch (ArgumentException) { throw Error(PbErrorKind.Text, "the string is not valid Unicode (unpaired surrogate)"); }
        }

        /// <summary>s in encoding enc (see Pb.Encodings).</summary>
        public byte[] TextBytes(string s, int enc)
        {
            try { return Pb.Encodings[enc].GetBytes(s); }
            catch (ArgumentException) { throw Error(PbErrorKind.Text, $"the string is not valid {Pb.EncodingNames[enc]}"); }
        }

        /// <summary>One variable-length integer (see PbReader.ReadVarint).</summary>
        public void WriteVarint(int kind, ulong v)
        {
            switch (kind)
            {
                case 5:
                    if (v < 0x80) WriteUint(v, 1, false);
                    else if (v <= 0x7fff) WriteUint(v | 0x8000, 2, false);
                    else throw Error(PbErrorKind.Range, $"{v} does not fit in a varint15");
                    return;
                case 4:
                    if (v <= 0x3f) WriteUint(v, 1, false);
                    else if (v <= 0x3fff) WriteUint(v | (1UL << 14), 2, false);
                    else if (v <= 0x3fffffff) WriteUint(v | (2UL << 30), 4, false);
                    else if (v <= 0x3fffffffffffffff) WriteUint(v | (3UL << 62), 8, false);
                    else throw Error(PbErrorKind.Range, $"{v} does not fit in a QUIC varint");
                    return;
                case 1:
                {
                    long x = unchecked((long)v);
                    while (true)
                    {
                        ulong b = (ulong)(x & 0x7f);
                        x >>= 7;
                        bool done = (x == 0 && (b & 0x40) == 0) || (x == -1 && (b & 0x40) != 0);
                        WriteUint(done ? b : b | 0x80, 1, false);
                        if (done) return;
                    }
                }
                case 3:
                {
                    var groups = new List<ulong> { v & 0x7f };
                    for (v >>= 7; v != 0; v >>= 7) groups.Add((v & 0x7f) | 0x80);
                    for (int i = groups.Count - 1; i >= 0; i--) WriteUint(groups[i], 1, false);
                    return;
                }
                default:
                    if (kind == 2) v = (v << 1) ^ unchecked((ulong)((long)v >> 63));
                    while (true)
                    {
                        ulong b = v & 0x7f;
                        v >>= 7;
                        WriteUint(v != 0 ? b | 0x80 : b, 1, false);
                        if (v == 0) return;
                    }
            }
        }

        public void CheckNoTerm(ReadOnlyMemory<byte> data, byte[] term) => CheckNoTerm(data.ToArray(), term);

        public void CheckNoTerm(byte[] data, byte[] term)
        {
            for (int i = 0; i + term.Length <= data.Length; i++)
            {
                bool hit = true;
                for (int k = 0; k < term.Length && hit; k++) hit = data[i + k] == term[k];
                if (hit) throw Error(PbErrorKind.Invalid, "the value contains its terminator");
            }
        }

        public void CheckFits(long length, long size)
        {
            if (length > size) throw Error(PbErrorKind.Range, $"{length} byte(s) do not fit in {size}");
        }

        public void CheckNoNul(byte[] data)
        {
            if (Array.IndexOf(data, (byte)0) >= 0) throw Error(PbErrorKind.Text, "the string contains a NUL byte");
        }

        public void CheckLen(long actual, long expected)
        {
            if (actual != expected)
                throw Error(PbErrorKind.Mismatch, $"{actual} element(s) but the length expression says {expected}");
        }

        public void CheckU(ulong v, int width)
        {
            if (width < 64 && (v >> width) != 0)
                throw Error(PbErrorKind.Range, $"value {v} does not fit in {width} bit(s)");
        }

        public void CheckI(long v, int width)
        {
            if (width < 64 && (v < -(1L << (width - 1)) || v > (1L << (width - 1)) - 1))
                throw Error(PbErrorKind.Range, $"value {v} does not fit in {width} signed bit(s)");
        }
    }

    internal static class Pb
    {
        internal static readonly System.Text.UTF8Encoding StrictUtf8 = new System.Text.UTF8Encoding(false, true);

        /// <summary>Strict text encodings by id: UTF-8, ASCII, Latin-1, UTF-16LE, UTF-16BE.</summary>
        internal static readonly System.Text.Encoding[] Encodings =
        {
            StrictUtf8,
            System.Text.Encoding.GetEncoding(20127, System.Text.EncoderFallback.ExceptionFallback, System.Text.DecoderFallback.ExceptionFallback),
            System.Text.Encoding.GetEncoding(28591, System.Text.EncoderFallback.ExceptionFallback, System.Text.DecoderFallback.ExceptionFallback),
            new System.Text.UnicodeEncoding(false, false, true),
            new System.Text.UnicodeEncoding(true, false, true),
        };

        internal static readonly string[] EncodingNames = { "UTF-8", "ASCII", "Latin-1", "UTF-16", "UTF-16" };

        /// <summary>Bytes as a JSON string of hex digits (for ToJson).</summary>
        public static string JsonHex(byte[] b) => "\"" + Convert.ToHexString(b).ToLowerInvariant() + "\"";

        public static string JsonHex(ReadOnlyMemory<byte> b) => JsonHex(b.ToArray());

        /// <summary>A JSON string literal (for ToJson).</summary>
        public static string JsonStr(string s)
        {
            var sb = new System.Text.StringBuilder("\"");
            foreach (char c in s)
            {
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                else sb.Append(c);
            }
            return sb.Append('"').ToString();
        }

        // CRC parameters by algorithm number: width, polynomial (reflected for
        // reflected CRCs), initial value, reflected, final XOR.
        private static readonly (int Width, ulong Poly, ulong Init, bool Reflected, ulong XorOut)[] Crc =
        {
            (8, 0x07, 0, false, 0),                          // crc8 (CRC-8/SMBUS)
            (16, 0xA001, 0, true, 0),                        // crc16_arc
            (16, 0x1021, 0xFFFF, false, 0),                  // crc16_ccitt_false (CRC-16/IBM-3740)
            (16, 0x1021, 0, false, 0),                       // crc16_xmodem
            (16, 0x8408, 0, true, 0),                        // crc16_kermit
            (16, 0xA001, 0xFFFF, true, 0),                   // crc16_modbus
            (32, 0xEDB88320, 0xFFFFFFFF, true, 0xFFFFFFFF),  // crc32 (CRC-32/ISO-HDLC)
            (32, 0x82F63B78, 0xFFFFFFFF, true, 0xFFFFFFFF),  // crc32c (CRC-32/ISCSI)
        };

        /// <summary>Checksum algo of buf[from..to) with buf[holeFrom..holeTo) as
        /// zeros. 8: Internet checksum (RFC 1071), 9: Fletcher-16, 10: sum8, 11: xor8,
        /// 12: sum16, 13: sum32_fold16.</summary>
        public static ulong Checksum(int algo, byte[] buf, long from, long to, long holeFrom, long holeTo)
        {
            ulong At(long i) => i >= holeFrom && i < holeTo ? 0UL : buf[i];
            if (algo < 8)
            {
                var p = Crc[algo];
                ulong mask = (1UL << p.Width) - 1, crc = p.Init;
                for (long i = from; i < to; i++)
                {
                    if (p.Reflected)
                    {
                        crc ^= At(i);
                        for (int k = 0; k < 8; k++) crc = (crc & 1) != 0 ? (crc >> 1) ^ p.Poly : crc >> 1;
                    }
                    else
                    {
                        crc ^= At(i) << (p.Width - 8);
                        for (int k = 0; k < 8; k++)
                            crc = ((crc & (1UL << (p.Width - 1))) != 0 ? (crc << 1) ^ p.Poly : crc << 1) & mask;
                    }
                }
                return (crc ^ p.XorOut) & mask;
            }
            ulong a = 0, b = 0;
            for (long i = from; i < to; i++)
            {
                ulong x = At(i);
                switch (algo)
                {
                    case 8: a += (i - from) % 2 == 0 ? x << 8 : x; break;
                    case 9: a = (a + x) % 255; b = (b + a) % 255; break;
                    case 10: a = (a + x) & 0xFF; break;
                    case 12: a = (a + x) & 0xFFFF; break;
                    case 13: a = (a + (x << (int)(8 * (3 - (i - from) % 4)))) & 0xFFFFFFFF; break;
                    default: a ^= x; break;
                }
            }
            if (algo == 8)
            {
                while ((a >> 16) != 0) a = (a & 0xFFFF) + (a >> 16);
                return ~a & 0xFFFF;
            }
            if (algo == 13) return ((a >> 16) + (a & 0xFFFF)) & 0xFFFF;
            return algo == 9 ? (b << 8) | a : a;
        }

        /// <summary>Padding needed after offset bits to reach a multiple of unit bits.</summary>
        public static long Pad(long offset, long unit) => (unit - offset % unit) % unit;

        public static long Sext(ulong v, int width)
        {
            if (width < 64 && ((v >> (width - 1)) & 1) == 1) v |= ulong.MaxValue << width;
            return unchecked((long)v);
        }

        public static long Trunc(long v, int width, bool signed)
        {
            if (width >= 64) return v;
            ulong u = unchecked((ulong)v) & ((1UL << width) - 1);
            return signed ? Sext(u, width) : (long)u;
        }

        public static long Div(long a, long b)
        {
            if (b == 0) return 0;
            if (b == -1) return unchecked(-a);
            return a / b;
        }

        public static long Mod(long a, long b)
        {
            if (b == 0 || b == -1) return 0;
            return a % b;
        }

        public static long Shl(long a, long b) => b < 0 || b > 63 ? 0 : a << (int)b;

        public static long Shr(long a, long b) => b < 0 ? 0 : a >> (int)Math.Min(b, 63);

        public static long Pow(long b, long e)
        {
            if (e < 0) return 0;
            long acc = 1;
            unchecked
            {
                for (ulong x = (ulong)e; x > 0; x >>= 1)
                {
                    if ((x & 1) == 1) acc *= b;
                    b *= b;
                }
            }
            return acc;
        }

        public static long FtoI(double v)
        {
            if (double.IsNaN(v)) return 0;
            if (v >= 9223372036854775807.0) return long.MaxValue;
            if (v <= -9223372036854775808.0) return long.MinValue;
            return (long)v;
        }

        public static T At<T>(T[] a, long i) where T : struct => i >= 0 && i < a.Length ? a[i] : default(T);

        public static byte At(ReadOnlyMemory<byte> a, long i) => i >= 0 && i < a.Length ? a.Span[(int)i] : (byte)0;

        /// <summary>The elements of an array, or of a zero-copy byte buffer.</summary>
        public static IEnumerable<T> Seq<T>(T[] a) => a;

        public static IEnumerable<byte> Seq(ReadOnlyMemory<byte> a) => a.ToArray();
    }

    // ---- generated packets --------------------------------------------------
