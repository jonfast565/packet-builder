    // ---- packet-builder runtime ---------------------------------------------

    /// <summary>Thrown when data cannot be decoded or a value cannot be encoded.</summary>
    public sealed class PbException : Exception
    {
        public PbException(string message) : base(message) { }
    }

    /// <summary>Reads integers of any bit width (MSB-first) and byte-aligned values.</summary>
    public sealed class PbReader
    {
        private readonly byte[] data;
        private long pos; // in bits

        public PbReader(byte[] data) { this.data = data; }

        public long RemainingBits => (long)data.Length * 8 - pos;

        private void Need(long bits)
        {
            if (bits < 0 || bits > RemainingBits)
                throw new PbException($"unexpected end of data: need {bits} more bit(s) at bit offset {pos}, have {RemainingBits}");
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

        public void SkipBits(long bits)
        {
            Need(bits);
            pos += bits;
        }

        /// <summary>Validate a decoded element count against the data that is left.</summary>
        public int Count(long n, long elemBits, string field)
        {
            if (n < 0) throw new PbException($"negative length {n} for field `{field}`");
            if (elemBits > 0 && n > RemainingBits / elemBits)
                throw new PbException($"length {n} for field `{field}` exceeds the remaining data");
            return (int)n;
        }
    }

    /// <summary>Builds a byte buffer; integers may be written at any bit position.</summary>
    public sealed class PbWriter
    {
        private readonly List<byte> buf = new List<byte>();
        private long pos; // in bits

        public byte[] ToArray() => buf.ToArray();

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

        public void WriteZeroBits(long bits)
        {
            for (; bits > 32; bits -= 32) WriteBits(0, 32);
            if (bits > 0) WriteBits(0, (int)bits);
        }
    }

    internal static class Pb
    {
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

        public static void CheckLen(long actual, long expected, string field)
        {
            if (actual != expected)
                throw new PbException($"field `{field}` has {actual} element(s) but its length expression says {expected}");
        }

        public static void CheckU(ulong v, int width, string field)
        {
            if (width < 64 && (v >> width) != 0)
                throw new PbException($"value {v} does not fit in {width} bit(s) for field `{field}`");
        }

        public static void CheckI(long v, int width, string field)
        {
            if (width < 64 && (v < -(1L << (width - 1)) || v > (1L << (width - 1)) - 1))
                throw new PbException($"value {v} does not fit in {width} signed bit(s) for field `{field}`");
        }
    }

    // ---- generated packets --------------------------------------------------
