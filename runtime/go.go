// ---- packet-builder runtime -------------------------------------------------

var _ = math.Sqrt

// PbError is returned when data cannot be decoded or a value cannot be encoded.
type PbError struct{ Msg string }

func (e *PbError) Error() string { return e.Msg }

func pbErrorf(format string, args ...any) error {
	return &PbError{Msg: fmt.Sprintf(format, args...)}
}

// PbReader reads integers of any bit width (MSB-first) and byte-aligned
// values. The first error is sticky: later reads return zero values.
type PbReader struct {
	data []byte
	pos  int // in bits
	err  error
}

func NewPbReader(data []byte) *PbReader { return &PbReader{data: data} }

func (r *PbReader) Err() error { return r.err }

func (r *PbReader) RemainingBits() int { return len(r.data)*8 - r.pos }

func (r *PbReader) need(bits int) bool {
	if r.err != nil {
		return false
	}
	if bits < 0 || bits > r.RemainingBits() {
		r.err = pbErrorf("unexpected end of data: need %d more bit(s) at bit offset %d, have %d", bits, r.pos, r.RemainingBits())
		return false
	}
	return true
}

func (r *PbReader) ReadBits(width int) uint64 {
	if !r.need(width) {
		return 0
	}
	var v uint64
	for left := width; left > 0; {
		b := r.data[r.pos>>3]
		off := r.pos & 7
		take := 8 - off
		if take > left {
			take = left
		}
		v = (v << uint(take)) | uint64((b>>uint(8-off-take))&byte((1<<uint(take))-1))
		r.pos += take
		left -= take
	}
	return v
}

func (r *PbReader) ReadUint(nbytes int, little bool) uint64 {
	if !r.need(nbytes * 8) {
		return 0
	}
	start := r.pos >> 3
	var v uint64
	for i := 0; i < nbytes; i++ {
		var b byte
		if little {
			b = r.data[start+nbytes-1-i]
		} else {
			b = r.data[start+i]
		}
		v = (v << 8) | uint64(b)
	}
	r.pos += nbytes * 8
	return v
}

func (r *PbReader) ReadBytes(n int) []byte {
	if !r.need(n * 8) {
		return []byte{}
	}
	start := r.pos >> 3
	r.pos += n * 8
	out := make([]byte, n)
	copy(out, r.data[start:start+n])
	return out
}

func (r *PbReader) ReadMac() (m [6]byte) {
	copy(m[:], r.ReadBytes(6))
	return m
}

func (r *PbReader) SkipBits(bits int) {
	if r.need(bits) {
		r.pos += bits
	}
}

// Count validates a decoded element count against the data that is left.
func (r *PbReader) Count(n int64, elemBits int, field string) int {
	if r.err != nil {
		return 0
	}
	if n < 0 {
		r.err = pbErrorf("negative length %d for field `%s`", n, field)
		return 0
	}
	if elemBits > 0 && n > int64(r.RemainingBits()/elemBits) {
		r.err = pbErrorf("length %d for field `%s` exceeds the remaining data", n, field)
		return 0
	}
	return int(n)
}

// PbWriter builds a byte buffer; integers may be written at any bit
// position. The first error is sticky.
type PbWriter struct {
	buf []byte
	pos int // in bits
	err error
}

func NewPbWriter() *PbWriter { return &PbWriter{} }

func (w *PbWriter) Err() error { return w.err }

func (w *PbWriter) Bytes() []byte { return w.buf }

func (w *PbWriter) WriteBits(value uint64, width int) {
	for left := width; left > 0; {
		if w.pos&7 == 0 {
			w.buf = append(w.buf, 0)
		}
		off := w.pos & 7
		take := 8 - off
		if take > left {
			take = left
		}
		bits := byte((value >> uint(left-take)) & ((1 << uint(take)) - 1))
		w.buf[len(w.buf)-1] |= bits << uint(8-off-take)
		w.pos += take
		left -= take
	}
}

func (w *PbWriter) WriteUint(value uint64, nbytes int, little bool) {
	for i := 0; i < nbytes; i++ {
		shift := 8 * (nbytes - 1 - i)
		if little {
			shift = 8 * i
		}
		w.buf = append(w.buf, byte(value>>uint(shift)))
	}
	w.pos += nbytes * 8
}

func (w *PbWriter) WriteBytes(data []byte) {
	w.buf = append(w.buf, data...)
	w.pos += len(data) * 8
}

func (w *PbWriter) WriteZeroBits(bits int64) {
	for ; bits > 32; bits -= 32 {
		w.WriteBits(0, 32)
	}
	if bits > 0 {
		w.WriteBits(0, int(bits))
	}
}

func (w *PbWriter) CheckLen(actual int, expected int64, field string) {
	if w.err == nil && int64(actual) != expected {
		w.err = pbErrorf("field `%s` has %d element(s) but its length expression says %d", field, actual, expected)
	}
}

func (w *PbWriter) CheckU(v uint64, width int, field string) {
	if w.err == nil && width < 64 && v>>uint(width) != 0 {
		w.err = pbErrorf("value %d does not fit in %d bit(s) for field `%s`", v, width, field)
	}
}

func (w *PbWriter) CheckI(v int64, width int, field string) {
	if w.err == nil && width < 64 && (v < -(int64(1)<<uint(width-1)) || v > (int64(1)<<uint(width-1))-1) {
		w.err = pbErrorf("value %d does not fit in %d signed bit(s) for field `%s`", v, width, field)
	}
}

type pbNumber interface {
	~int8 | ~uint8 | ~int16 | ~uint16 | ~int32 | ~uint32 | ~int64 | ~uint64 | ~float32 | ~float64
}

func pbSext(v uint64, width int) int64 {
	if width < 64 && (v>>uint(width-1))&1 == 1 {
		return int64(v | (^uint64(0) << uint(width)))
	}
	return int64(v)
}

func pbTrunc(v int64, width int, signed bool) int64 {
	if width >= 64 {
		return v
	}
	u := uint64(v) & ((uint64(1) << uint(width)) - 1)
	if signed {
		return pbSext(u, width)
	}
	return int64(u)
}

func pbVal[T any](v T) T { return v }

func pbB2I(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func pbIf[T any](c bool, a, b T) T {
	if c {
		return a
	}
	return b
}

func pbMin[T int64 | float64](a, b T) T {
	if b < a {
		return b
	}
	return a
}

func pbMax[T int64 | float64](a, b T) T {
	if b > a {
		return b
	}
	return a
}

func pbDiv(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func pbFDiv(a, b float64) float64 { return a / b }

func pbPow(base, exp int64) int64 {
	if exp < 0 {
		return 0
	}
	acc := int64(1)
	for e := uint64(exp); e > 0; e >>= 1 {
		if e&1 == 1 {
			acc *= base
		}
		base *= base
	}
	return acc
}

func pbAt[T pbNumber](s []T, i int64) T {
	if i < 0 || i >= int64(len(s)) {
		var zero T
		return zero
	}
	return s[i]
}

func pbSum[T pbNumber](s []T) (acc int64) {
	for _, v := range s {
		acc += int64(v)
	}
	return acc
}

func pbProd[T pbNumber](s []T) int64 {
	acc := int64(1)
	for _, v := range s {
		acc *= int64(v)
	}
	return acc
}

func pbSumF[T pbNumber](s []T) (acc float64) {
	for _, v := range s {
		acc += float64(v)
	}
	return acc
}

func pbProdF[T pbNumber](s []T) float64 {
	acc := 1.0
	for _, v := range s {
		acc *= float64(v)
	}
	return acc
}

// ---- generated packets ------------------------------------------------------
