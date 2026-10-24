// ---- packet-builder runtime -------------------------------------------------

var _ = math.Sqrt
var _ = utf8.Valid
var _ = strings.Builder{}
var _ = sort.Ints
var _ = strconv.Itoa

// pbJSONHex returns bytes as a JSON string of hex digits (for ToJSON).
func pbJSONHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b)+2)
	out = append(out, '"')
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(append(out, '"'))
}

// pbJSONStr returns s as a JSON string literal (for ToJSON).
func pbJSONStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

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
type pbTrace struct {
	frames  []pbFrame
	version int // protocol version; 0 until set
}

// @versions{
func (t *pbTrace) versionOr(latest int) int64 {
	if t.version == 0 {
		return int64(latest)
	}
	return int64(t.version)
}

func pbVersionOk(v int64, min, latest int) bool { return v >= int64(min) && v <= int64(latest) }

// VersionOr is the protocol version (`version`), or latest while none is set.
func (r *PbReader) VersionOr(latest int) int64 { return r.tr.versionOr(latest) }

// SetVersion decodes as protocol version v, which must be in min..latest.
func (r *PbReader) SetVersion(v int64, min, latest int) {
	if !pbVersionOk(v, min, latest) {
		r.Fail(PbConstraint, "version %d is not one of the versions %d..%d", v, min, latest)
		return
	}
	r.tr.version = int(v)
}

// VersionOr is the protocol version (`version`), or latest while none is set.
func (w *PbWriter) VersionOr(latest int) int64 { return w.tr.versionOr(latest) }

// SetVersion encodes as protocol version v, which must be in min..latest.
func (w *PbWriter) SetVersion(v int64, min, latest int) {
	if !pbVersionOk(v, min, latest) {
		w.Fail(PbConstraint, "version %d is not one of the versions %d..%d", v, min, latest)
		return
	}
	w.tr.version = int(v)
}

// AdoptVersion takes the version a value carries in-band, unless one is set.
func (w *PbWriter) AdoptVersion(v int64, min, latest int) {
	if w.tr.version == 0 {
		w.SetVersion(v, min, latest)
	}
}
// @versions}

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
	data    []byte
	pos     int // in bits
	limit   int // end of the readable data in bits (a window inside data)
	windows int // windows open
	err     error
	tr      pbTrace
}

func NewPbReader(data []byte) *PbReader { return &PbReader{data: data, limit: len(data) * 8} }

// PbJump is where a reader was before Jump.
type PbJump struct{ pos, limit, windows int }

// Jump reads from offset bytes after bit from (the packet start, or 0 for
// the start of the input) until JumpBack; windows do not apply there.
func (r *PbReader) Jump(from int, offset int64) PbJump {
	saved := PbJump{r.pos, r.limit, r.windows}
	if r.err != nil {
		return saved
	}
	if offset < 0 || from%8 != 0 || offset > int64(len(r.data)) || from+int(offset)*8 > len(r.data)*8 {
		r.Fail(PbInvalid, "offset %d is past the end of the input", offset)
		return saved
	}
	r.pos, r.limit, r.windows = from+int(offset)*8, len(r.data)*8, 0
	return saved
}

// JumpBack returns to where Jump left.
func (r *PbReader) JumpBack(j PbJump) { r.pos, r.limit, r.windows = j.pos, j.limit, j.windows }

func (r *PbReader) Err() error { return r.err }

func (r *PbReader) RemainingBits() int { return r.limit - r.pos }

// RemainingBytes is the whole bytes left before the end of the window or input (`remaining`).
func (r *PbReader) RemainingBytes() int64 { return int64(r.RemainingBits() / 8) }

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
	if r.windows == 0 {
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
	r.windows++
	return saved
}

// PopLimit skips what is left of the current window and restores saved;
// with exact, bytes left over are an error.
func (r *PbReader) PopLimit(saved int, exact bool) {
	if exact && r.err == nil && r.RemainingBits() > 0 {
		r.Fail(PbInvalid, "%d bit(s) left over in a field that must fill its size", r.RemainingBits())
	}
	if r.err == nil {
		r.pos = r.limit
	}
	r.limit = saved
	if r.windows > 0 {
		r.windows--
	}
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

// ReadBytesRef returns the next n bytes as a slice of the input (zero-copy;
// its capacity ends with it, so appending copies).
func (r *PbReader) ReadBytesRef(n int) []byte {
	if !r.need(n * 8) {
		return []byte{}
	}
	start := r.pos >> 3
	r.pos += n * 8
	return r.data[start : start+n : start+n]
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

// TextEnc decodes raw in encoding enc (0 UTF-8, 1 ASCII, 2 Latin-1,
// 3 UTF-16LE, 4 UTF-16BE); padded cuts it at the first NUL character.
func (r *PbReader) TextEnc(raw []byte, enc int, padded bool) string {
	if enc == 0 {
		return r.Text(raw, padded)
	}
	var sb strings.Builder
	if enc <= 2 {
		for _, b := range raw {
			if b == 0 && padded {
				break
			}
			if enc == 1 && b >= 0x80 {
				r.Fail(PbText, "invalid ASCII")
				return ""
			}
			sb.WriteRune(rune(b))
		}
		return sb.String()
	}
	if len(raw)%2 != 0 {
		r.Fail(PbText, "invalid UTF-16 (an odd number of bytes)")
		return ""
	}
	unit := func(i int) rune {
		if enc == 3 {
			return rune(raw[i]) | rune(raw[i+1])<<8
		}
		return rune(raw[i])<<8 | rune(raw[i+1])
	}
	for i := 0; i < len(raw); i += 2 {
		u := unit(i)
		if u == 0 && padded {
			break
		}
		if u >= 0xD800 && u <= 0xDBFF && i+3 < len(raw) {
			if lo := unit(i + 2); lo >= 0xDC00 && lo <= 0xDFFF {
				sb.WriteRune(0x10000 + (u-0xD800)<<10 + (lo - 0xDC00))
				i += 2
				continue
			}
		}
		if u >= 0xD800 && u <= 0xDFFF {
			r.Fail(PbText, "invalid UTF-16")
			return ""
		}
		sb.WriteRune(u)
	}
	return sb.String()
}

// ReadVarint reads one variable-length integer (kind: 0 uleb128, 1 sleb128,
// 2 zigzag, 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.
func (r *PbReader) ReadVarint(kind int) uint64 {
	if kind == 5 {
		first := r.ReadUint(1, false)
		if first&0x80 == 0 {
			return first
		}
		return (first&0x7f)<<8 | r.ReadUint(1, false)
	}
	if kind == 4 {
		first := r.ReadUint(1, false)
		n := 1 << (first >> 6)
		v := first & 0x3f
		if n > 1 {
			v = v<<(8*uint(n-1)) | r.ReadUint(n-1, false)
		}
		return v
	}
	var v uint64
	shift := 0
	for r.err == nil {
		b := r.ReadUint(1, false)
		if kind == 3 {
			if v>>57 != 0 {
				r.Fail(PbInvalid, "the varint does not fit in 64 bits")
				return 0
			}
			v = v<<7 | b&0x7f
		} else {
			// The 10th byte holds bit 63 only (and, for sleb128, its sign).
			lastOK := b&0x7e == 0
			if kind == 1 {
				lastOK = b&0x7f == 0 || b&0x7f == 0x7f
			}
			if shift >= 64 || (shift == 63 && (b&0x80 != 0 || !lastOK)) {
				r.Fail(PbInvalid, "the varint does not fit in 64 bits")
				return 0
			}
			v |= (b & 0x7f) << uint(shift)
		}
		shift += 7
		if b&0x80 == 0 {
			if kind == 1 && shift < 64 && b&0x40 != 0 {
				v |= ^uint64(0) << uint(shift)
			}
			break
		}
	}
	if kind == 2 {
		v = v>>1 ^ -(v & 1)
	}
	return v
}

// ReadUntil returns the bytes before term and consumes both. Without the
// terminator it returns the rest of the input when optional, else fails.
func (r *PbReader) ReadUntil(term []byte, optional bool) []byte {
	return append([]byte{}, r.ReadUntilRef(term, optional)...)
}

// ReadUntilRef is ReadUntil returning a slice of the input (zero-copy).
func (r *PbReader) ReadUntilRef(term []byte, optional bool) []byte {
	if r.err != nil {
		return []byte{}
	}
	start, end := r.pos>>3, r.limit>>3
	for i := start; i+len(term) <= end; i++ {
		if string(r.data[i:i+len(term)]) == string(term) {
			r.pos = (i + len(term)) * 8
			return r.data[start:i:i]
		}
	}
	if !optional {
		r.short(r.RemainingBits()+8, "the terminated field")
		return []byte{}
	}
	r.pos = r.limit
	return r.data[start:end:end]
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

// Checksum computes algorithm algo over the input between two bit positions
// (whole bytes); the bytes between holeFrom and holeTo count as zero.
func (r *PbReader) Checksum(algo, from, to, holeFrom, holeTo int) uint64 {
	return pbChecksum(algo, r.data, from/8, to/8, holeFrom/8, holeTo/8)
}

// PbWriter builds a byte buffer; integers may be written at any bit
// position. The first error is sticky.
type PbWriter struct {
	buf []byte
	pos int // in bits
	err error
	tr  pbTrace
	// base is where buf goes in the output, in bits (non-zero for Sub writers).
	base int
	// placed holds packets placed at an offset (`at`); Finish writes them.
	placed []pbPlaced
}

type pbPlaced struct {
	at   int
	data []byte
	path string
}

func NewPbWriter() *PbWriter { return &PbWriter{} }

// Sub returns a writer for a packet placed offset bytes after bit from of
// this writer (the packet start), or after the start of the output (root).
func (w *PbWriter) Sub(from int, offset int64, root bool) *PbWriter {
	start := w.base + from
	if root {
		start = 0
	}
	s := &PbWriter{tr: pbTrace{frames: append([]pbFrame{}, w.tr.frames...), version: w.tr.version}}
	if offset < 0 || start%8 != 0 {
		w.Fail(PbRange, "bad offset %d (from bit %d)", offset, start)
		return s
	}
	s.base = start + int(offset)*8
	return s
}

// Place keeps what s wrote, for Finish.
func (w *PbWriter) Place(s *PbWriter) {
	if w.err == nil {
		w.err = s.err
	}
	w.placed = append(w.placed, pbPlaced{s.base / 8, s.buf, w.tr.path()})
	w.placed = append(w.placed, s.placed...)
}

// Finish returns the output with every placed packet written at its offset:
// past the end (zero-filling the gap), or over bytes that must already match.
func (w *PbWriter) Finish() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	sort.SliceStable(w.placed, func(i, j int) bool { return w.placed[i].at < w.placed[j].at })
	for _, pl := range w.placed {
		// The output reaches the offset even when the packet is empty.
		for len(w.buf) < pl.at {
			w.buf = append(w.buf, 0)
		}
		for i, b := range pl.data {
			k := pl.at + i
			switch {
			case k < len(w.buf):
				if w.buf[k] != b {
					msg := fmt.Sprintf("the packet placed at byte %d does not match the bytes already there", pl.at)
					return nil, &PbError{Kind: PbMismatch, Msg: msg, Path: pl.path, BitOffset: k * 8}
				}
			default:
				for len(w.buf) < k {
					w.buf = append(w.buf, 0)
				}
				w.buf = append(w.buf, b)
			}
		}
	}
	w.placed = nil
	return w.buf, nil
}

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

// CheckNoTerm fails if a terminated value contains its terminator.
func (w *PbWriter) CheckNoTerm(data, term []byte) {
	for i := 0; i+len(term) <= len(data); i++ {
		if string(data[i:i+len(term)]) == string(term) {
			w.Fail(PbInvalid, "the value contains its terminator")
			return
		}
	}
}

// EncodeText encodes s in encoding enc (see PbReader.TextEnc).
func (w *PbWriter) EncodeText(s string, enc int) []byte {
	if enc == 0 {
		return []byte(s)
	}
	out := []byte{}
	for _, c := range s {
		switch {
		case enc == 1 && c > 0x7f:
			w.Fail(PbText, "%q is not ASCII", c)
			return out
		case enc == 2 && c > 0xff:
			w.Fail(PbText, "%q is not Latin-1", c)
			return out
		case enc <= 2:
			out = append(out, byte(c))
		default:
			units := []rune{c}
			if c >= 0x10000 {
				c -= 0x10000
				units = []rune{0xD800 + c>>10, 0xDC00 + c&0x3FF}
			}
			for _, u := range units {
				if enc == 3 {
					out = append(out, byte(u), byte(u>>8))
				} else {
					out = append(out, byte(u>>8), byte(u))
				}
			}
		}
	}
	return out
}

// WriteVarint writes one variable-length integer (see PbReader.ReadVarint).
func (w *PbWriter) WriteVarint(kind int, v uint64) {
	switch kind {
	case 5:
		switch {
		case v < 0x80:
			w.WriteUint(v, 1, false)
		case v <= 0x7fff:
			w.WriteUint(v|0x8000, 2, false)
		default:
			w.Fail(PbRange, "%d does not fit in a varint15", v)
		}
	case 4:
		switch {
		case v <= 0x3f:
			w.WriteUint(v, 1, false)
		case v <= 0x3fff:
			w.WriteUint(v|1<<14, 2, false)
		case v <= 0x3fffffff:
			w.WriteUint(v|2<<30, 4, false)
		case v <= 0x3fffffffffffffff:
			w.WriteUint(v|3<<62, 8, false)
		default:
			w.Fail(PbRange, "%d does not fit in a QUIC varint", v)
		}
	case 1:
		x := int64(v)
		for {
			b := uint64(x & 0x7f)
			x >>= 7
			done := (x == 0 && b&0x40 == 0) || (x == -1 && b&0x40 != 0)
			if done {
				w.WriteUint(b, 1, false)
				return
			}
			w.WriteUint(b|0x80, 1, false)
		}
	case 3:
		groups := []uint64{v & 0x7f}
		for v >>= 7; v != 0; v >>= 7 {
			groups = append(groups, v&0x7f|0x80)
		}
		for i := len(groups) - 1; i >= 0; i-- {
			w.WriteUint(groups[i], 1, false)
		}
	default:
		if kind == 2 {
			v = v<<1 ^ uint64(int64(v)>>63)
		}
		for {
			b := v & 0x7f
			v >>= 7
			if v == 0 {
				w.WriteUint(b, 1, false)
				return
			}
			w.WriteUint(b|0x80, 1, false)
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

// EndWindow ends a window of size bytes that started at bit start: the
// content must fit (and fill it when exact); the rest is zero-filled.
func (w *PbWriter) EndWindow(start int, size int64, exact bool) {
	used := w.pos - start
	if size < 0 || int64(used) > size*8 {
		w.Fail(PbRange, "the content takes %d bit(s), more than its size of %d byte(s)", used, size)
		return
	}
	if exact && int64(used) != size*8 {
		w.Fail(PbMismatch, "the content takes %d bit(s) but must fill its %d byte(s)", used, size)
		return
	}
	w.WriteZeroBits(size*8 - int64(used))
}

// PatchUint overwrites nbytes bytes at bit position at (byte aligned).
func (w *PbWriter) PatchUint(at int, value uint64, nbytes int, little bool) {
	if at/8+nbytes > len(w.buf) {
		return // only after an earlier error
	}
	for i := 0; i < nbytes; i++ {
		shift := 8 * (nbytes - 1 - i)
		if little {
			shift = 8 * i
		}
		w.buf[at/8+i] = byte(value >> uint(shift))
	}
}

// PatchBits overwrites width bits at bit position at, MSB first.
func (w *PbWriter) PatchBits(at int, value uint64, width int) {
	if (at+width+7)/8 > len(w.buf) {
		return // only after an earlier error
	}
	for i := 0; i < width; i++ {
		bit := byte((value >> uint(width-1-i)) & 1)
		b, off := (at+i)/8, uint(7-(at+i)%8)
		w.buf[b] = (w.buf[b] &^ (1 << off)) | (bit << off)
	}
}

// Checksum computes algorithm algo over the output between two bit
// positions (whole bytes); the bytes between holeFrom and holeTo count as zero.
func (w *PbWriter) Checksum(algo, from, to, holeFrom, holeTo int) uint64 {
	return pbChecksum(algo, w.buf, from/8, to/8, holeFrom/8, holeTo/8)
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

// pbSize is the number of whole bytes between two bit positions.
func pbSize(from, to int) int64 { return int64((to - from) / 8) }

// pbCRC holds the CRC parameters by algorithm number: width, polynomial
// (reflected for reflected CRCs), initial value, reflected, final XOR.
var pbCRC = [8]struct {
	width      int
	poly, init uint64
	reflected  bool
	xorout     uint64
}{
	{8, 0x07, 0, false, 0},                         // crc8 (CRC-8/SMBUS)
	{16, 0xa001, 0, true, 0},                       // crc16_arc
	{16, 0x1021, 0xffff, false, 0},                 // crc16_ccitt_false (CRC-16/IBM-3740)
	{16, 0x1021, 0, false, 0},                      // crc16_xmodem
	{16, 0x8408, 0, true, 0},                       // crc16_kermit
	{16, 0xa001, 0xffff, true, 0},                  // crc16_modbus
	{32, 0xedb88320, 0xffffffff, true, 0xffffffff}, // crc32 (CRC-32/ISO-HDLC)
	{32, 0x82f63b78, 0xffffffff, true, 0xffffffff}, // crc32c (CRC-32/ISCSI)
}

// pbChecksum computes algorithm algo over buf[from:to] with
// buf[holeFrom:holeTo] as zeros. 8: Internet checksum (RFC 1071),
// 9: Fletcher-16, 10: sum8, 11: xor8, 12: sum16, 13: sum32_fold16.
func pbChecksum(algo int, buf []byte, from, to, holeFrom, holeTo int) uint64 {
	at := func(i int) uint64 {
		if i >= holeFrom && i < holeTo {
			return 0
		}
		return uint64(buf[i])
	}
	switch {
	case algo < 8:
		p := pbCRC[algo]
		mask := uint64(1)<<uint(p.width) - 1
		crc := p.init
		for i := from; i < to; i++ {
			if p.reflected {
				crc ^= at(i)
				for k := 0; k < 8; k++ {
					if crc&1 != 0 {
						crc = crc>>1 ^ p.poly
					} else {
						crc >>= 1
					}
				}
			} else {
				crc ^= at(i) << uint(p.width-8)
				for k := 0; k < 8; k++ {
					if crc&(1<<uint(p.width-1)) != 0 {
						crc = (crc<<1 ^ p.poly) & mask
					} else {
						crc = crc << 1 & mask
					}
				}
			}
		}
		return (crc ^ p.xorout) & mask
	case algo == 8:
		var sum uint64
		for i := from; i < to; i++ {
			if (i-from)%2 == 0 {
				sum += at(i) << 8
			} else {
				sum += at(i)
			}
		}
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
		return ^sum & 0xffff
	case algo == 9:
		var a, b uint64
		for i := from; i < to; i++ {
			a = (a + at(i)) % 255
			b = (b + a) % 255
		}
		return b<<8 | a
	case algo == 10:
		var a uint64
		for i := from; i < to; i++ {
			a = (a + at(i)) & 0xff
		}
		return a
	case algo == 12:
		var a uint64
		for i := from; i < to; i++ {
			a = (a + at(i)) & 0xffff
		}
		return a
	case algo == 13:
		var a uint64
		for i := from; i < to; i++ {
			a = (a + at(i)<<uint(8*(3-(i-from)%4))) & 0xffffffff
		}
		return (a>>16 + a&0xffff) & 0xffff
	default:
		var a uint64
		for i := from; i < to; i++ {
			a ^= at(i)
		}
		return a
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
