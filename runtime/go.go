// ---- packet-builder runtime -------------------------------------------------

var _ = math.Sqrt
var _ = utf8.Valid
var _ = strings.Builder{}

// PbErrorKind says what went wrong while decoding or encoding.
type PbErrorKind int

const (
	// PbIncomplete: the input ended before the packet did; NeededBits more would help.
	PbIncomplete PbErrorKind = iota + 1
	// PbInvalid: malformed data (a bad length, nesting too deep, ...).
	PbInvalid
	// PbRange: a value does not fit in its field.
	PbRange
	// PbText: a string is not valid text, or contains a NUL where none is allowed.
	PbText
	// PbMismatch: a length, derived field or checksum does not match the data.
	PbMismatch
	// PbConstraint: a value breaks a declared constraint.
	PbConstraint
)

func (k PbErrorKind) String() string {
	switch k {
	case PbIncomplete:
		return "incomplete"
	case PbInvalid:
		return "invalid"
	case PbRange:
		return "range"
	case PbText:
		return "text"
	case PbMismatch:
		return "mismatch"
	case PbConstraint:
		return "constraint"
	}
	return "unknown"
}

// PbError is returned when data cannot be decoded or a value cannot be encoded.
type PbError struct {
	Kind PbErrorKind
	Msg  string
	// Path is where it happened: Packet.field[index].field.
	Path       string
	BitOffset  int
	NeededBits int // for PbIncomplete
}

func (e *PbError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("%s (at bit %d)", e.Msg, e.BitOffset)
	}
	return fmt.Sprintf("%s: %s (at bit %d)", e.Path, e.Msg, e.BitOffset)
}

// PbMaxDepth is the deepest packet nesting accepted.
const PbMaxDepth = 64

type pbFrame struct {
	packet, field string
	index         int
}

// pbTrace holds the packets being decoded or encoded, innermost last, each
// with the field it is working on: the path reported in errors.
type pbTrace struct{ frames []pbFrame }

func (t *pbTrace) enter(packet string) bool {
	t.frames = append(t.frames, pbFrame{packet, "", -1})
	return len(t.frames) <= PbMaxDepth
}

func (t *pbTrace) leave() {
	if len(t.frames) > 0 {
		t.frames = t.frames[:len(t.frames)-1]
	}
}

func (t *pbTrace) at(field string) {
	if n := len(t.frames); n > 0 {
		t.frames[n-1].field = field
		t.frames[n-1].index = -1
	}
}

func (t *pbTrace) atIndex(i int) {
	if n := len(t.frames); n > 0 {
		t.frames[n-1].index = i
	}
}

func (t *pbTrace) path() string {
	var b strings.Builder
	if len(t.frames) > 0 {
		b.WriteString(t.frames[0].packet)
	}
	for _, f := range t.frames {
		if f.field == "" {
			break
		}
		b.WriteString(".")
		b.WriteString(f.field)
		if f.index >= 0 {
			fmt.Fprintf(&b, "[%d]", f.index)
		}
	}
	return b.String()
}

// PbReader reads integers of any bit width (MSB-first) and byte-aligned
// values. The first error is sticky: later reads return zero values.
type PbReader struct {
	data  []byte
	pos   int // in bits
	limit int // end of the readable data in bits (a window inside data)
	err   error
	tr    pbTrace
}

func NewPbReader(data []byte) *PbReader { return &PbReader{data: data, limit: len(data) * 8} }

func (r *PbReader) Err() error { return r.err }

func (r *PbReader) RemainingBits() int { return r.limit - r.pos }

func (r *PbReader) PositionBits() int { return r.pos }

// Fail records the first error at the current position.
func (r *PbReader) Fail(kind PbErrorKind, format string, args ...any) {
	if r.err == nil {
		r.err = &PbError{Kind: kind, Msg: fmt.Sprintf(format, args...), Path: r.tr.path(), BitOffset: r.pos}
	}
}

// short records that bits more bits are needed than are left: incomplete
// input at the top level, invalid data inside a window.
func (r *PbReader) short(bits int, what string) {
	if r.err != nil {
		return
	}
	if r.limit == len(r.data)*8 {
		r.Fail(PbIncomplete, "unexpected end of data: %s needs %d more bit(s), %d left", what, bits, r.RemainingBits())
		r.err.(*PbError).NeededBits = bits - r.RemainingBits()
	} else {
		r.Fail(PbInvalid, "%s needs %d bit(s) but its window has %d left", what, bits, r.RemainingBits())
	}
}

func (r *PbReader) need(bits int) bool {
	if r.err != nil {
		return false
	}
	if bits < 0 || bits > r.RemainingBits() {
		r.short(bits, "the field")
		return false
	}
	return true
}

func (r *PbReader) Enter(packet string) {
	if !r.tr.enter(packet) {
		r.Fail(PbInvalid, "packets nested more than %d deep", PbMaxDepth)
	}
}

func (r *PbReader) Leave()          { r.tr.leave() }
func (r *PbReader) At(field string) { r.tr.at(field) }
func (r *PbReader) AtIndex(i int)   { r.tr.atIndex(i) }

// PushLimit restricts reading to the next n bytes and returns the previous
// limit for PopLimit.
func (r *PbReader) PushLimit(n int64) int {
	saved := r.limit
	if r.err != nil {
		return saved
	}
	if n < 0 {
		r.Fail(PbInvalid, "negative size %d", n)
		return saved
	}
	if n > int64(r.RemainingBits()/8) {
		r.short(int(n)*8, "the window")
		return saved
	}
	r.limit = r.pos + int(n)*8
	return saved
}

// PopLimit skips what is left of the current window and restores saved.
func (r *PbReader) PopLimit(saved int) {
	if r.err == nil {
		r.pos = r.limit
	}
	r.limit = saved
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

// ReadCString returns the bytes before a NUL terminator and consumes it.
func (r *PbReader) ReadCString() []byte {
	if r.err != nil {
		return nil
	}
	start := r.pos >> 3
	for i := start; i < r.limit>>3; i++ {
		if r.data[i] == 0 {
			r.pos = (i + 1) * 8
			out := make([]byte, i-start)
			copy(out, r.data[start:i])
			return out
		}
	}
	r.short(r.RemainingBits()+8, "the NUL-terminated string")
	return nil
}

// Text validates raw as UTF-8; untilNul cuts it at the first NUL byte.
func (r *PbReader) Text(raw []byte, untilNul bool) string {
	if untilNul {
		for i, b := range raw {
			if b == 0 {
				raw = raw[:i]
				break
			}
		}
	}
	if r.err == nil && !utf8.Valid(raw) {
		r.Fail(PbText, "invalid UTF-8")
	}
	return string(raw)
}

// Count validates a decoded element count against the data that is left.
func (r *PbReader) Count(n int64, elemBits int) int {
	if r.err != nil {
		return 0
	}
	if n < 0 {
		r.Fail(PbInvalid, "negative length %d", n)
		return 0
	}
	if elemBits > 0 && n > int64(r.RemainingBits()/elemBits) {
		bits := n * int64(elemBits)
		if bits/int64(elemBits) != n || bits > int64(^uint(0)>>1) {
			bits = int64(^uint(0) >> 1)
		}
		r.short(int(bits), fmt.Sprintf("length %d", n))
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
	tr  pbTrace
}

func NewPbWriter() *PbWriter { return &PbWriter{} }

func (w *PbWriter) Err() error { return w.err }

func (w *PbWriter) Bytes() []byte { return w.buf }

func (w *PbWriter) PositionBits() int { return w.pos }

// Fail records the first error at the current position.
func (w *PbWriter) Fail(kind PbErrorKind, format string, args ...any) {
	if w.err == nil {
		w.err = &PbError{Kind: kind, Msg: fmt.Sprintf(format, args...), Path: w.tr.path(), BitOffset: w.pos}
	}
}

func (w *PbWriter) Enter(packet string) {
	if !w.tr.enter(packet) {
		w.Fail(PbInvalid, "packets nested more than %d deep", PbMaxDepth)
	}
}

func (w *PbWriter) Leave()          { w.tr.leave() }
func (w *PbWriter) At(field string) { w.tr.at(field) }
func (w *PbWriter) AtIndex(i int)   { w.tr.atIndex(i) }

func (w *PbWriter) CheckFits(length int, size int64) {
	if int64(length) > size {
		w.Fail(PbRange, "%d byte(s) do not fit in %d", length, size)
	}
}

func (w *PbWriter) CheckUTF8(s string) {
	if !utf8.ValidString(s) {
		w.Fail(PbText, "invalid UTF-8")
	}
}

func (w *PbWriter) CheckNoNul(data []byte) {
	for _, b := range data {
		if b == 0 {
			w.Fail(PbText, "the string contains a NUL byte")
			return
		}
	}
}

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

func (w *PbWriter) CheckLen(actual int, expected int64) {
	if int64(actual) != expected {
		w.Fail(PbMismatch, "%d element(s) but the length expression says %d", actual, expected)
	}
}

func (w *PbWriter) CheckU(v uint64, width int) {
	if width < 64 && v>>uint(width) != 0 {
		w.Fail(PbRange, "value %d does not fit in %d bit(s)", v, width)
	}
}

func (w *PbWriter) CheckI(v int64, width int) {
	if width < 64 && (v < -(int64(1)<<uint(width-1)) || v > (int64(1)<<uint(width-1))-1) {
		w.Fail(PbRange, "value %d does not fit in %d signed bit(s)", v, width)
	}
}

type pbNumber interface {
	~int8 | ~uint8 | ~int16 | ~uint16 | ~int32 | ~uint32 | ~int64 | ~uint64 | ~float32 | ~float64
}

// pbPad is the padding needed after offset bits to reach a multiple of unit bits.
func pbPad(offset, unit int) int { return (unit - offset%unit) % unit }

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

func pbMod(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return a % b
}

func pbShl(a, b int64) int64 {
	if b < 0 || b > 63 {
		return 0
	}
	return a << uint(b)
}

func pbShr(a, b int64) int64 {
	if b < 0 {
		return 0
	}
	if b > 63 {
		b = 63
	}
	return a >> uint(b)
}

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
