  ! ---- packet-builder runtime --------------------------------------------

  !> Error kinds (pb_error%kind); PB_OK means no error.
  integer, parameter :: PB_OK = 0
  !> The input ended before the packet did; needed_bits more would help.
  integer, parameter :: PB_INCOMPLETE = 1
  !> Malformed data: a bad length, nesting too deep, ...
  integer, parameter :: PB_INVALID = 2
  !> A value does not fit in its field.
  integer, parameter :: PB_RANGE = 3
  !> A string is not valid text, or contains a NUL where none is allowed.
  integer, parameter :: PB_TEXT = 4
  !> A length, derived field or checksum does not match the data.
  integer, parameter :: PB_MISMATCH = 5
  !> A value breaks a declared constraint.
  integer, parameter :: PB_CONSTRAINT = 6
  !> The deepest packet nesting accepted.
  integer, parameter :: PB_MAX_DEPTH = 64
  !> The smallest int64.
  integer(int64), parameter :: PB_MIN64 = ishft(1_int64, 63)

  !> What went wrong while decoding or encoding (kind PB_OK: nothing).
  type :: pb_error
    integer :: kind = PB_OK
    !> "path: reason (at bit N)".
    character(len=:), allocatable :: message
    character(len=:), allocatable :: reason
    !> Where it happened: Packet.field[index].field.
    character(len=:), allocatable :: path
    integer(int64) :: bit_offset = 0
    !> For PB_INCOMPLETE: the least number of extra input bits needed.
    integer(int64) :: needed_bits = 0
  end type pb_error

  type :: pb_frame
    character(len=:), allocatable :: packet
    character(len=:), allocatable :: field
    integer(int64) :: index = -1
  end type pb_frame

  !> The packets being decoded or encoded, innermost last, each with the
  !> field it is working on (the path reported in errors), the position in
  !> bits, the protocol version (0 until set) and the first error.
  type :: pb_trace
    type(pb_frame) :: frames(PB_MAX_DEPTH + 1)
    integer :: depth = 0
    integer(int64) :: pos = 0
    integer(int64) :: version = 0
    type(pb_error) :: e
  end type pb_trace

  !> Reads integers of any bit width (MSB-first) and byte-aligned values.
  type, extends(pb_trace) :: pb_reader
    integer(int8), allocatable :: data(:)
    !> End of the readable data in bits (a window inside the data).
    integer(int64) :: limit = 0
    integer :: windows = 0
  end type pb_reader

  !> Where a reader was before pb_jump.
  type :: pb_jump_state
    integer(int64) :: pos = 0
    integer(int64) :: limit = 0
    integer :: windows = 0
  end type pb_jump_state

  type :: pb_placed
    integer(int64) :: at = 0
    integer(int8), allocatable :: data(:)
    character(len=:), allocatable :: path
  end type pb_placed

  !> Builds a byte buffer; integers may be written at any bit position.
  type, extends(pb_trace) :: pb_writer
    integer(int8), allocatable :: buf(:)
    integer(int64) :: n = 0
    !> Where the buffer goes in the output, in bits (sub writers).
    integer(int64) :: base = 0
    type(pb_placed), allocatable :: placed(:)
    integer :: nplaced = 0
  end type pb_writer

  !> A string builder (for to_json).
  type :: pb_sb
    character(len=:), allocatable :: s
    integer :: n = 0
  end type pb_sb

  !> An element of an array of hardware addresses.
  type :: pb_mac
    integer(int8) :: b(6) = 0_int8
  end type pb_mac

  !> An element of an array of strings.
  type :: pb_string
    character(len=:), allocatable :: s
  end type pb_string

  !> Element I (from 0) of an array as int64 or real64; 0 when out of range.
  interface pb_elem
    module procedure pb_elem_i8, pb_elem_i16, pb_elem_i32, pb_elem_i64, pb_elem_r32, pb_elem_r64
  end interface pb_elem

  !> The sum (wrapping) of an array's elements.
  interface pb_sum
    module procedure pb_sum_i8, pb_sum_i16, pb_sum_i32, pb_sum_i64, pb_sum_r32, pb_sum_r64
  end interface pb_sum

  !> The product (wrapping) of an array's elements.
  interface pb_product
    module procedure pb_product_i8, pb_product_i16, pb_product_i32, pb_product_i64, pb_product_r32, pb_product_r64
  end interface pb_product

  !> Elements of an array, 0 when it is not allocated.
  interface pb_size
    module procedure pb_size_i8, pb_size_i16, pb_size_i32, pb_size_i64, pb_size_r32, pb_size_r64, pb_size_mac
  end interface pb_size

  ! @contains

  ! ---- packet-builder runtime --------------------------------------------

  !> The name of an error kind (incomplete, invalid, ...).
  pure function pb_kind_name(kind) result(s)
    integer, intent(in) :: kind
    character(len=:), allocatable :: s
    select case (kind)
    case (PB_OK)
      s = 'ok'
    case (PB_INCOMPLETE)
      s = 'incomplete'
    case (PB_INVALID)
      s = 'invalid'
    case (PB_RANGE)
      s = 'range'
    case (PB_TEXT)
      s = 'text'
    case (PB_MISMATCH)
      s = 'mismatch'
    case default
      s = 'constraint'
    end select
  end function pb_kind_name

  !> A decimal integer.
  pure function pb_itoa(v) result(s)
    integer(int64), intent(in) :: v
    character(len=:), allocatable :: s
    character(len=20) :: buf
    integer(int64) :: x
    integer :: i
    if (v == 0) then
      s = '0'
      return
    end if
    i = 21
    x = v
    do while (x /= 0)
      i = i - 1
      buf(i:i) = achar(48 + int(abs(mod(x, 10_int64))))
      x = x / 10_int64
    end do
    if (v < 0) then
      s = '-' // buf(i:20)
    else
      s = buf(i:20)
    end if
  end function pb_itoa

  !> The bits of V as an unsigned decimal integer.
  pure function pb_utoa(v) result(s)
    integer(int64), intent(in) :: v
    character(len=:), allocatable :: s
    integer(int64) :: q
    if (v >= 0) then
      s = pb_itoa(v)
      return
    end if
    q = shiftr(v, 1) / 5_int64
    s = pb_itoa(q) // achar(48 + int(pb_subt(v, pb_mul(q, 10_int64))))
  end function pb_utoa

  ! -- the trace and errors

  !> Record an error (the first one sticks) with an explicit path and offset.
  pure subroutine pb_set_error(t, kind, reason, path, bit, needed)
    class(pb_trace), intent(inout) :: t
    integer, intent(in) :: kind
    character(len=*), intent(in) :: reason, path
    integer(int64), intent(in) :: bit, needed
    if (t%e%kind /= PB_OK) return
    t%e%kind = kind
    t%e%reason = reason
    t%e%path = path
    t%e%bit_offset = bit
    t%e%needed_bits = needed
    if (len(path) > 0) then
      t%e%message = path // ': ' // reason // ' (at bit ' // pb_itoa(bit) // ')'
    else
      t%e%message = reason // ' (at bit ' // pb_itoa(bit) // ')'
    end if
  end subroutine pb_set_error

  !> Record an error at the current field and position.
  pure subroutine pb_fail(t, kind, reason, needed)
    class(pb_trace), intent(inout) :: t
    integer, intent(in) :: kind
    character(len=*), intent(in) :: reason
    integer(int64), intent(in), optional :: needed
    integer(int64) :: n
    n = 0
    if (present(needed)) n = needed
    call pb_set_error(t, kind, reason, pb_path(t), t%pos, n)
  end subroutine pb_fail

  pure subroutine pb_enter(t, packet)
    class(pb_trace), intent(inout) :: t
    character(len=*), intent(in) :: packet
    if (t%depth >= PB_MAX_DEPTH + 1) then
      call pb_fail(t, PB_INVALID, 'packets nested more than ' // pb_itoa(int(PB_MAX_DEPTH, int64)) // ' deep')
      return
    end if
    t%depth = t%depth + 1
    t%frames(t%depth)%packet = packet
    t%frames(t%depth)%field = ''
    t%frames(t%depth)%index = -1
    if (t%depth > PB_MAX_DEPTH) then
      call pb_fail(t, PB_INVALID, 'packets nested more than ' // pb_itoa(int(PB_MAX_DEPTH, int64)) // ' deep')
    end if
  end subroutine pb_enter

  pure subroutine pb_leave(t)
    class(pb_trace), intent(inout) :: t
    if (t%depth > 0) t%depth = t%depth - 1
  end subroutine pb_leave

  pure subroutine pb_at(t, field)
    class(pb_trace), intent(inout) :: t
    character(len=*), intent(in) :: field
    if (t%depth < 1) return
    t%frames(t%depth)%field = field
    t%frames(t%depth)%index = -1
  end subroutine pb_at

  pure subroutine pb_at_index(t, index)
    class(pb_trace), intent(inout) :: t
    integer(int64), intent(in) :: index
    if (t%depth < 1) return
    t%frames(t%depth)%index = index
  end subroutine pb_at_index

  !> Packet.field[index].field for the frames entered.
  pure function pb_path(t) result(s)
    class(pb_trace), intent(in) :: t
    character(len=:), allocatable :: s
    integer :: i
    s = ''
    if (t%depth > 0) s = t%frames(1)%packet
    do i = 1, t%depth
      if (.not. allocated(t%frames(i)%field)) exit
      if (len(t%frames(i)%field) == 0) exit
      s = s // '.' // t%frames(i)%field
      if (t%frames(i)%index >= 0) s = s // '[' // pb_itoa(t%frames(i)%index) // ']'
    end do
  end function pb_path

  ! @versions{
  !> The protocol version (`version`), or LATEST while none is set.
  pure function pb_version_or(t, latest) result(v)
    class(pb_trace), intent(in) :: t
    integer, intent(in) :: latest
    integer(int64) :: v
    if (t%version == 0) then
      v = int(latest, int64)
    else
      v = t%version
    end if
  end function pb_version_or

  !> Code as protocol version V, which must be in VMIN..LATEST.
  pure subroutine pb_set_version(t, v, vmin, latest)
    class(pb_trace), intent(inout) :: t
    integer(int64), intent(in) :: v
    integer, intent(in) :: vmin, latest
    if (v < vmin .or. v > latest) then
      call pb_fail(t, PB_CONSTRAINT, 'version ' // pb_itoa(v) // ' is not one of the versions ' // &
        pb_itoa(int(vmin, int64)) // '..' // pb_itoa(int(latest, int64)))
      return
    end if
    t%version = v
  end subroutine pb_set_version

  !> The version a value carries in-band: used unless one is set already.
  pure subroutine pb_adopt_version(t, v, vmin, latest)
    class(pb_trace), intent(inout) :: t
    integer(int64), intent(in) :: v
    integer, intent(in) :: vmin, latest
    if (t%version == 0) call pb_set_version(t, v, vmin, latest)
  end subroutine pb_adopt_version
  ! @versions}

  !> Fail with KIND and REASON unless COND holds.
  pure subroutine pb_check(t, cond, kind, reason)
    class(pb_trace), intent(inout) :: t
    logical, intent(in) :: cond
    integer, intent(in) :: kind
    character(len=*), intent(in) :: reason
    if (.not. cond) call pb_fail(t, kind, reason)
  end subroutine pb_check

  ! -- bytes

  !> A byte as 0..255.
  elemental function pb_u8(b) result(v)
    integer(int8), intent(in) :: b
    integer(int64) :: v
    v = iand(int(b, int64), 255_int64)
  end function pb_u8

  !> The low 8 bits of V as a byte.
  elemental function pb_i8(v) result(b)
    integer(int64), intent(in) :: v
    integer(int8) :: b
    integer(int64) :: x
    x = iand(v, 255_int64)
    if (x > 127) x = x - 256
    b = int(x, int8)
  end function pb_i8

  ! -- the reader

  !> A reader of DATA, from its first bit.
  pure subroutine pb_reader_init(r, data)
    type(pb_reader), intent(out) :: r
    integer(int8), intent(in) :: data(:)
    allocate(r%data(0:size(data) - 1))
    if (size(data) > 0) r%data(0:) = data
    r%limit = 8_int64 * size(data, kind=int64)
  end subroutine pb_reader_init

  pure function pb_remaining_bits(r) result(v)
    type(pb_reader), intent(in) :: r
    integer(int64) :: v
    v = r%limit - r%pos
  end function pb_remaining_bits

  !> Whole bytes left before the end of the window or input (`remaining`).
  pure function pb_remaining_bytes(r) result(v)
    type(pb_reader), intent(in) :: r
    integer(int64) :: v
    v = (r%limit - r%pos) / 8_int64
  end function pb_remaining_bytes

  pure function pb_data_bits(r) result(v)
    type(pb_reader), intent(in) :: r
    integer(int64) :: v
    v = 0
    if (allocated(r%data)) v = 8_int64 * size(r%data, kind=int64)
  end function pb_data_bits

  !> Not enough data for BITS bits of WHAT.
  pure subroutine pb_short(r, bits, what)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: bits
    character(len=*), intent(in) :: what
    integer(int64) :: left
    left = pb_remaining_bits(r)
    if (r%windows == 0) then
      call pb_fail(r, PB_INCOMPLETE, 'unexpected end of data: ' // what // ' needs ' // pb_itoa(bits) // &
        ' more bit(s), ' // pb_itoa(left) // ' left', bits - left)
    else
      call pb_fail(r, PB_INVALID, what // ' needs ' // pb_itoa(bits) // ' bit(s) but its window has ' // &
        pb_itoa(left) // ' left')
    end if
  end subroutine pb_short

  !> True when BITS more bits can be read; otherwise records the error.
  function pb_need(r, bits) result(ok)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: bits
    logical :: ok
    ok = r%e%kind == PB_OK
    if (.not. ok) return
    if (bits < 0 .or. bits > pb_remaining_bits(r)) then
      call pb_short(r, bits, 'the field')
      ok = .false.
    end if
  end function pb_need

  !> Read from OFFSET bytes after bit FROM (the packet start, or 0 for the
  !> start of the input) until pb_jump_back; windows do not apply there.
  pure subroutine pb_jump(r, from, offset, saved)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: from, offset
    type(pb_jump_state), intent(out) :: saved
    integer(int64) :: total
    total = pb_data_bits(r)
    if (offset < 0 .or. mod(from, 8_int64) /= 0 .or. offset > total / 8) then
      call pb_fail(r, PB_INVALID, 'offset ' // pb_itoa(offset) // ' is past the end of the input')
      return
    end if
    if (from + offset * 8 > total) then
      call pb_fail(r, PB_INVALID, 'offset ' // pb_itoa(offset) // ' is past the end of the input')
      return
    end if
    saved%pos = r%pos
    saved%limit = r%limit
    saved%windows = r%windows
    r%pos = from + offset * 8
    r%limit = total
    r%windows = 0
  end subroutine pb_jump

  !> Return to where pb_jump left.
  pure subroutine pb_jump_back(r, saved)
    type(pb_reader), intent(inout) :: r
    type(pb_jump_state), intent(in) :: saved
    r%pos = saved%pos
    r%limit = saved%limit
    r%windows = saved%windows
  end subroutine pb_jump_back

  !> Restrict reading to the next N bytes; returns the previous limit.
  function pb_push_limit(r, n) result(saved)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: n
    integer(int64) :: saved
    saved = r%limit
    if (n < 0) then
      call pb_fail(r, PB_INVALID, 'negative size ' // pb_itoa(n))
      return
    end if
    if (n > pb_remaining_bits(r) / 8) then
      call pb_short(r, n * 8, 'the window')
      return
    end if
    r%limit = r%pos + n * 8
    r%windows = r%windows + 1
  end function pb_push_limit

  !> Skip what is left of the current window and restore SAVED; with EXACT,
  !> bits left over are an error.
  pure subroutine pb_pop_limit(r, saved, exact)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: saved
    logical, intent(in) :: exact
    if (exact .and. pb_remaining_bits(r) > 0) then
      call pb_fail(r, PB_INVALID, pb_itoa(pb_remaining_bits(r)) // ' bit(s) left over in a field that must fill its size')
      return
    end if
    r%pos = r%limit
    r%limit = saved
    r%windows = r%windows - 1
  end subroutine pb_pop_limit

  !> WIDTH (0..64) bits, MSB first, as the low bits of the result.
  function pb_read_bits(r, width) result(v)
    type(pb_reader), intent(inout) :: r
    integer, intent(in) :: width
    integer(int64) :: v
    integer :: left, off, take
    integer(int64) :: b
    v = 0
    if (.not. pb_need(r, int(width, int64))) return
    left = width
    do while (left > 0)
      b = pb_u8(r%data(shiftr(r%pos, 3)))
      off = int(iand(r%pos, 7_int64))
      take = min(8 - off, left)
      v = ior(ishft(v, take), iand(shiftr(b, 8 - off - take), maskr(take, int64)))
      r%pos = r%pos + take
      left = left - take
    end do
  end function pb_read_bits

  !> NBYTES (1..8) whole bytes as an unsigned integer (bit pattern).
  function pb_read_uint(r, nbytes, little) result(v)
    type(pb_reader), intent(inout) :: r
    integer, intent(in) :: nbytes
    logical, intent(in) :: little
    integer(int64) :: v
    integer(int64) :: start
    integer :: i
    v = 0
    if (.not. pb_need(r, 8_int64 * nbytes)) return
    start = shiftr(r%pos, 3)
    do i = 0, nbytes - 1
      if (little) then
        v = ior(ishft(v, 8), pb_u8(r%data(start + nbytes - 1 - i)))
      else
        v = ior(ishft(v, 8), pb_u8(r%data(start + i)))
      end if
    end do
    r%pos = r%pos + 8_int64 * nbytes
  end function pb_read_uint

  subroutine pb_read_bytes(r, n, out)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: n
    integer(int8), allocatable, intent(out) :: out(:)
    integer(int64) :: start
    if (n < 0 .or. n > pb_remaining_bits(r) / 8) then
      if (.not. pb_need(r, -1_int64)) return
    end if
    if (.not. pb_need(r, n * 8)) return
    start = shiftr(r%pos, 3)
    allocate(out(n))
    if (n > 0) out(1:n) = r%data(start:start + n - 1)
    r%pos = r%pos + n * 8
  end subroutine pb_read_bytes

  subroutine pb_read_mac(r, out)
    type(pb_reader), intent(inout) :: r
    integer(int8), intent(out) :: out(6)
    integer(int64) :: start
    out = 0_int8
    if (.not. pb_need(r, 48_int64)) return
    start = shiftr(r%pos, 3)
    out = r%data(start:start + 5)
    r%pos = r%pos + 48
  end subroutine pb_read_mac

  subroutine pb_skip_bits(r, bits)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: bits
    if (.not. pb_need(r, bits)) return
    r%pos = r%pos + bits
  end subroutine pb_skip_bits

  !> Bytes before a NUL terminator; the terminator is consumed.
  pure subroutine pb_read_cstring(r, out)
    type(pb_reader), intent(inout) :: r
    integer(int8), allocatable, intent(out) :: out(:)
    integer(int64) :: start, i, stop
    if (r%e%kind /= PB_OK) return
    start = shiftr(r%pos, 3)
    stop = shiftr(r%limit, 3)
    i = start
    do while (i < stop)
      if (r%data(i) == 0) exit
      i = i + 1
    end do
    if (i >= stop) then
      call pb_short(r, pb_remaining_bits(r) + 8, 'the NUL-terminated string')
      return
    end if
    allocate(out(i - start))
    if (i > start) out(1:i - start) = r%data(start:i - 1)
    r%pos = (i + 1) * 8
  end subroutine pb_read_cstring

  !> Validate a decoded element count against the data that is left.
  function pb_count(r, n, elem_bits) result(c)
    type(pb_reader), intent(inout) :: r
    integer(int64), intent(in) :: n, elem_bits
    integer(int64) :: c
    integer(int64) :: bits
    c = 0
    if (n < 0) then
      call pb_fail(r, PB_INVALID, 'negative length ' // pb_itoa(n))
      return
    end if
    if (elem_bits > 0) then
      if (n > pb_remaining_bits(r) / elem_bits) then
        if (n > huge(n) / elem_bits) then
          bits = huge(n)
        else
          bits = n * elem_bits
        end if
        call pb_short(r, bits, 'length ' // pb_itoa(n))
        return
      end if
    end if
    c = n
  end function pb_count

  !> The bytes before TERM, consuming both. Without the terminator: the
  !> rest of the input when OPTIONAL, otherwise an error.
  pure subroutine pb_read_until(r, term, optional, out)
    type(pb_reader), intent(inout) :: r
    integer(int8), intent(in) :: term(:)
    logical, intent(in) :: optional
    integer(int8), allocatable, intent(out) :: out(:)
    integer(int64) :: start, stop, i, nt
    if (r%e%kind /= PB_OK) return
    start = shiftr(r%pos, 3)
    stop = shiftr(r%limit, 3)
    nt = size(term, kind=int64)
    i = start
    do while (i + nt <= stop)
      if (all(r%data(i:i + nt - 1) == term)) then
        allocate(out(i - start))
        if (i > start) out(1:i - start) = r%data(start:i - 1)
        r%pos = (i + nt) * 8
        return
      end if
      i = i + 1
    end do
    if (.not. optional) then
      call pb_short(r, pb_remaining_bits(r) + 8, 'the terminated field')
      return
    end if
    allocate(out(max(stop - start, 0_int64)))
    if (stop > start) out(1:stop - start) = r%data(start:stop - 1)
    r%pos = r%limit
  end subroutine pb_read_until

  !> One variable-length integer (kind: 0 uleb128, 1 sleb128, 2 zigzag,
  !> 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.
  function pb_read_varint(r, kind) result(v)
    type(pb_reader), intent(inout) :: r
    integer, intent(in) :: kind
    integer(int64) :: v
    integer(int64) :: first, b, rest
    integer :: n, shift
    logical :: last_ok
    v = 0
    if (kind == 5) then
      first = pb_read_uint(r, 1, .false.)
      if (r%e%kind /= PB_OK) return
      if (iand(first, 128_int64) == 0) then
        v = first
        return
      end if
      rest = pb_read_uint(r, 1, .false.)
      v = ior(ishft(iand(first, 127_int64), 8), rest)
      return
    end if
    if (kind == 4) then
      first = pb_read_uint(r, 1, .false.)
      if (r%e%kind /= PB_OK) return
      n = 2 ** int(shiftr(first, 6))
      v = iand(first, 63_int64)
      if (n > 1) then
        rest = pb_read_uint(r, n - 1, .false.)
        v = ior(ishft(v, 8 * (n - 1)), rest)
      end if
      return
    end if
    shift = 0
    do
      b = pb_read_uint(r, 1, .false.)
      if (r%e%kind /= PB_OK) return
      if (kind == 3) then
        if (shiftr(v, 57) /= 0) then
          call pb_fail(r, PB_INVALID, 'the varint does not fit in 64 bits')
          return
        end if
        v = ior(ishft(v, 7), iand(b, 127_int64))
      else
        ! The 10th byte holds bit 63 only (and, for sleb128, its sign).
        if (kind == 1) then
          last_ok = iand(b, 127_int64) == 0 .or. iand(b, 127_int64) == 127
        else
          last_ok = iand(b, 126_int64) == 0
        end if
        if (shift >= 64) then
          call pb_fail(r, PB_INVALID, 'the varint does not fit in 64 bits')
          return
        end if
        if (shift == 63 .and. (iand(b, 128_int64) /= 0 .or. .not. last_ok)) then
          call pb_fail(r, PB_INVALID, 'the varint does not fit in 64 bits')
          return
        end if
        v = ior(v, ishft(iand(b, 127_int64), shift))
      end if
      shift = shift + 7
      if (iand(b, 128_int64) == 0) then
        if (kind == 1 .and. shift < 64) then
          if (iand(b, 64_int64) /= 0) v = ior(v, ishft(-1_int64, shift))
        end if
        exit
      end if
    end do
    if (kind == 2) v = ieor(shiftr(v, 1), -iand(v, 1_int64))
  end function pb_read_varint

  !> Checksum ALGO of the input between two bit positions (whole bytes);
  !> the bytes between HOLE_FROM and HOLE_TO count as zero.
  pure function pb_reader_checksum(r, algo, from, to, hole_from, hole_to) result(v)
    type(pb_reader), intent(in) :: r
    integer, intent(in) :: algo
    integer(int64), intent(in) :: from, to, hole_from, hole_to
    integer(int64) :: v
    v = pb_checksum(algo, r%data, from / 8, to / 8, hole_from / 8, hole_to / 8)
  end function pb_reader_checksum

  ! -- text

  !> The code points of UTF-8 bytes RAW(1:N); false unless strictly valid
  !> (no overlong forms, surrogates or values past U+10FFFF).
  pure subroutine pb_utf8_points(raw, n, cps, ncp, ok)
    integer(int8), intent(in) :: raw(:)
    integer(int64), intent(in) :: n
    integer(int32), allocatable, intent(out) :: cps(:)
    integer(int64), intent(out) :: ncp
    logical, intent(out) :: ok
    integer(int64) :: i, c, b
    integer :: more, k
    allocate(cps(n))
    ncp = 0
    ok = .false.
    i = 1
    do while (i <= n)
      c = pb_u8(raw(i))
      if (c < 128) then
        more = 0
      else if (c >= 194 .and. c <= 223) then
        more = 1
        c = iand(c, 31_int64)
      else if (c >= 224 .and. c <= 239) then
        more = 2
        c = iand(c, 15_int64)
      else if (c >= 240 .and. c <= 244) then
        more = 3
        c = iand(c, 7_int64)
      else
        return
      end if
      do k = 1, more
        if (i + k > n) return
        b = pb_u8(raw(i + k))
        if (iand(b, 192_int64) /= 128) return
        c = ior(ishft(c, 6), iand(b, 63_int64))
      end do
      if (more == 2) then
        if (c < 2048 .or. (c >= 55296 .and. c <= 57343)) return
      end if
      if (more == 3) then
        if (c < 65536 .or. c > 1114111) return
      end if
      i = i + more + 1
      ncp = ncp + 1
      cps(ncp) = int(c, int32)
    end do
    ok = .true.
  end subroutine pb_utf8_points

  !> Code points as UTF-8 text.
  pure subroutine pb_points_utf8(cps, ncp, s)
    integer(int32), intent(in) :: cps(:)
    integer(int64), intent(in) :: ncp
    character(len=:), allocatable, intent(out) :: s
    character(len=:), allocatable :: t
    integer(int64) :: i, n, c
    allocate(character(len=4 * ncp) :: t)
    n = 0
    do i = 1, ncp
      c = cps(i)
      if (c < 128) then
        t(n + 1:n + 1) = achar(c)
        n = n + 1
      else if (c < 2048) then
        t(n + 1:n + 1) = char(ior(192_int64, shiftr(c, 6)))
        t(n + 2:n + 2) = char(ior(128_int64, iand(c, 63_int64)))
        n = n + 2
      else if (c < 65536) then
        t(n + 1:n + 1) = char(ior(224_int64, shiftr(c, 12)))
        t(n + 2:n + 2) = char(ior(128_int64, iand(shiftr(c, 6), 63_int64)))
        t(n + 3:n + 3) = char(ior(128_int64, iand(c, 63_int64)))
        n = n + 3
      else
        t(n + 1:n + 1) = char(ior(240_int64, shiftr(c, 18)))
        t(n + 2:n + 2) = char(ior(128_int64, iand(shiftr(c, 12), 63_int64)))
        t(n + 3:n + 3) = char(ior(128_int64, iand(shiftr(c, 6), 63_int64)))
        t(n + 4:n + 4) = char(ior(128_int64, iand(c, 63_int64)))
        n = n + 4
      end if
    end do
    s = t(1:n)
  end subroutine pb_points_utf8

  !> Bytes as characters.
  pure subroutine pb_bytes_text(raw, n, s)
    integer(int8), intent(in) :: raw(:)
    integer(int64), intent(in) :: n
    character(len=:), allocatable, intent(out) :: s
    integer(int64) :: i
    allocate(character(len=n) :: s)
    do i = 1, n
      s(i:i) = char(pb_u8(raw(i)))
    end do
  end subroutine pb_bytes_text

  !> Text in encoding ENC (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
  !> 4 UTF-16BE), as UTF-8; PADDED cuts it at the first NUL character.
  pure subroutine pb_decode_text(r, raw, enc, padded, s)
    type(pb_reader), intent(inout) :: r
    integer(int8), allocatable, intent(in) :: raw(:)
    integer, intent(in) :: enc
    logical, intent(in) :: padded
    character(len=:), allocatable, intent(out) :: s
    integer(int32), allocatable :: cps(:)
    integer(int64) :: n, i, units, ncp, c, d
    logical :: ok
    s = ''
    if (r%e%kind /= PB_OK) return
    if (.not. allocated(raw)) return
    n = size(raw, kind=int64)
    units = 1
    if (enc >= 3) units = 2
    if (mod(n, units) /= 0) then
      call pb_fail(r, PB_TEXT, 'invalid UTF-16 (an odd number of bytes)')
      return
    end if
    if (padded) then
      i = 1
      do while (i <= n)
        if (raw(i) == 0 .and. raw(i + units - 1) == 0) then
          n = i - 1
          exit
        end if
        i = i + units
      end do
    end if
    if (enc == 0) then
      call pb_utf8_points(raw, n, cps, ncp, ok)
      if (.not. ok) then
        call pb_fail(r, PB_TEXT, 'invalid UTF-8')
        return
      end if
      call pb_bytes_text(raw, n, s)
      return
    end if
    allocate(cps(n / units))
    ncp = 0
    i = 1
    do while (i <= n)
      select case (enc)
      case (3)
        c = ior(pb_u8(raw(i)), ishft(pb_u8(raw(i + 1)), 8))
      case (4)
        c = ior(ishft(pb_u8(raw(i)), 8), pb_u8(raw(i + 1)))
      case default
        c = pb_u8(raw(i))
      end select
      i = i + units
      if (enc == 1 .and. c > 127) then
        call pb_fail(r, PB_TEXT, 'invalid ASCII')
        return
      end if
      if (enc >= 3) then
        ! Surrogates come in pairs: a high one, then a low one.
        if (c >= 56320 .and. c <= 57343) then
          call pb_fail(r, PB_TEXT, 'invalid UTF-16')
          return
        end if
        if (c >= 55296 .and. c <= 56319) then
          if (i > n) then
            call pb_fail(r, PB_TEXT, 'invalid UTF-16')
            return
          end if
          if (enc == 3) then
            d = ior(pb_u8(raw(i)), ishft(pb_u8(raw(i + 1)), 8))
          else
            d = ior(ishft(pb_u8(raw(i)), 8), pb_u8(raw(i + 1)))
          end if
          if (d < 56320 .or. d > 57343) then
            call pb_fail(r, PB_TEXT, 'invalid UTF-16')
            return
          end if
          i = i + 2
          c = 65536 + ishft(c - 55296, 10) + (d - 56320)
        end if
      end if
      ncp = ncp + 1
      cps(ncp) = int(c, int32)
    end do
    call pb_points_utf8(cps, ncp, s)
  end subroutine pb_decode_text

  !> The bytes a string takes in UTF-8 (0 when it is not allocated).
  pure function pb_strlen(s) result(n)
    character(len=:), allocatable, intent(in) :: s
    integer(int64) :: n
    n = 0
    if (allocated(s)) n = len(s, kind=int64)
  end function pb_strlen

  ! -- the writer

  !> Room for N more bytes.
  pure subroutine pb_reserve(w, n)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: n
    integer(int8), allocatable :: t(:)
    integer(int64) :: cap
    if (.not. allocated(w%buf)) allocate(w%buf(0:max(n, 64_int64) - 1))
    if (w%n + n <= size(w%buf, kind=int64)) return
    cap = max(w%n + n, 2 * size(w%buf, kind=int64))
    allocate(t(0:cap - 1))
    if (w%n > 0) t(0:w%n - 1) = w%buf(0:w%n - 1)
    call move_alloc(t, w%buf)
  end subroutine pb_reserve

  pure subroutine pb_add_byte(w, b)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: b
    call pb_reserve(w, 1_int64)
    w%buf(w%n) = pb_i8(b)
    w%n = w%n + 1
  end subroutine pb_add_byte

  !> The bytes written so far.
  pure subroutine pb_writer_bytes(w, out)
    type(pb_writer), intent(in) :: w
    integer(int8), allocatable, intent(out) :: out(:)
    allocate(out(w%n))
    if (w%n > 0) out(1:w%n) = w%buf(0:w%n - 1)
  end subroutine pb_writer_bytes

  !> A writer for a packet placed OFFSET bytes after bit FROM of this
  !> writer (the packet start), or after the start of the output (ROOT).
  pure subroutine pb_sub_writer(w, from, offset, root, s)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: from, offset
    logical, intent(in) :: root
    type(pb_writer), intent(out) :: s
    integer(int64) :: start
    integer :: i
    if (root) then
      start = 0
    else
      start = w%base + from
    end if
    if (offset < 0 .or. mod(start, 8_int64) /= 0) then
      call pb_fail(w, PB_RANGE, 'bad offset ' // pb_itoa(offset) // ' (from bit ' // pb_itoa(start) // ')')
      return
    end if
    s%base = start + offset * 8
    do i = 1, w%depth
      s%frames(i) = w%frames(i)
    end do
    s%depth = w%depth
    s%version = w%version
  end subroutine pb_sub_writer

  !> Keep what S wrote (and the packets it placed), for pb_finish; passes
  !> on its error.
  pure subroutine pb_place(w, s)
    type(pb_writer), intent(inout) :: w
    type(pb_writer), intent(in) :: s
    type(pb_placed), allocatable :: t(:)
    integer :: i, need
    if (s%e%kind /= PB_OK) then
      if (w%e%kind == PB_OK) w%e = s%e
      return
    end if
    need = w%nplaced + 1 + s%nplaced
    if (.not. allocated(w%placed)) allocate(w%placed(max(need, 4)))
    if (need > size(w%placed)) then
      allocate(t(max(need, 2 * size(w%placed))))
      do i = 1, w%nplaced
        call move_alloc(w%placed(i)%data, t(i)%data)
        call move_alloc(w%placed(i)%path, t(i)%path)
        t(i)%at = w%placed(i)%at
      end do
      call move_alloc(t, w%placed)
    end if
    w%nplaced = w%nplaced + 1
    w%placed(w%nplaced)%at = s%base / 8
    call pb_writer_bytes(s, w%placed(w%nplaced)%data)
    w%placed(w%nplaced)%path = pb_path(w)
    do i = 1, s%nplaced
      w%nplaced = w%nplaced + 1
      w%placed(w%nplaced) = s%placed(i)
    end do
  end subroutine pb_place

  !> The output, with every placed packet written at its offset: past the
  !> end (zero-filling the gap), or over bytes that must already match.
  pure subroutine pb_finish(w, out)
    type(pb_writer), intent(inout) :: w
    integer(int8), allocatable, intent(out) :: out(:)
    type(pb_placed) :: t
    integer :: i, j
    integer(int64) :: k, m
    ! Insertion sort by offset, stable like the other runtimes.
    do i = 2, w%nplaced
      t = w%placed(i)
      j = i - 1
      do while (j >= 1)
        if (w%placed(j)%at <= t%at) exit
        w%placed(j + 1) = w%placed(j)
        j = j - 1
      end do
      w%placed(j + 1) = t
    end do
    do i = 1, w%nplaced
      ! The output reaches the offset even when the packet is empty.
      do while (w%n < w%placed(i)%at)
        call pb_add_byte(w, 0_int64)
      end do
      do m = 1, size(w%placed(i)%data, kind=int64)
        k = w%placed(i)%at + m - 1
        if (k < w%n) then
          if (w%buf(k) /= w%placed(i)%data(m)) then
            call pb_set_error(w, PB_MISMATCH, 'the packet placed at byte ' // pb_itoa(w%placed(i)%at) // &
              ' does not match the bytes already there', w%placed(i)%path, k * 8, 0_int64)
            return
          end if
        else
          do while (w%n < k)
            call pb_add_byte(w, 0_int64)
          end do
          call pb_add_byte(w, pb_u8(w%placed(i)%data(m)))
        end if
      end do
    end do
    w%nplaced = 0
    call pb_writer_bytes(w, out)
  end subroutine pb_finish

  !> The low WIDTH (0..64) bits of VALUE, MSB first.
  pure subroutine pb_write_bits(w, value, width)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: value
    integer, intent(in) :: width
    integer :: left, off, take
    integer(int64) :: bits, cur
    left = width
    do while (left > 0)
      if (iand(w%pos, 7_int64) == 0) call pb_add_byte(w, 0_int64)
      off = int(iand(w%pos, 7_int64))
      take = min(8 - off, left)
      bits = iand(shiftr(value, left - take), maskr(take, int64))
      cur = ior(pb_u8(w%buf(w%n - 1)), ishft(bits, 8 - off - take))
      w%buf(w%n - 1) = pb_i8(cur)
      w%pos = w%pos + take
      left = left - take
    end do
  end subroutine pb_write_bits

  pure subroutine pb_write_uint(w, value, nbytes, little)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: value
    integer, intent(in) :: nbytes
    logical, intent(in) :: little
    integer :: i, shift
    do i = 0, nbytes - 1
      if (little) then
        shift = 8 * i
      else
        shift = 8 * (nbytes - 1 - i)
      end if
      call pb_add_byte(w, iand(shiftr(value, shift), 255_int64))
    end do
    w%pos = w%pos + 8_int64 * nbytes
  end subroutine pb_write_uint

  pure subroutine pb_write_bytes(w, bytes)
    type(pb_writer), intent(inout) :: w
    integer(int8), intent(in) :: bytes(:)
    integer(int64) :: n
    n = size(bytes, kind=int64)
    if (n == 0) return
    call pb_reserve(w, n)
    w%buf(w%n:w%n + n - 1) = bytes
    w%n = w%n + n
    w%pos = w%pos + 8 * n
  end subroutine pb_write_bytes

  !> A byte buffer (nothing when it is not allocated).
  pure subroutine pb_write_buf(w, bytes)
    type(pb_writer), intent(inout) :: w
    integer(int8), allocatable, intent(in) :: bytes(:)
    if (allocated(bytes)) call pb_write_bytes(w, bytes)
  end subroutine pb_write_buf

  pure subroutine pb_write_zero_bits(w, bits)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: bits
    integer(int64) :: left
    left = bits
    do while (left > 32)
      call pb_write_bits(w, 0_int64, 32)
      left = left - 32
    end do
    if (left > 0) call pb_write_bits(w, 0_int64, int(left))
  end subroutine pb_write_zero_bits

  !> End a window of SIZE bytes that started at bit START: the content
  !> must fit (and fill it when EXACT); the rest is zero-filled.
  pure subroutine pb_end_window(w, start, size, exact)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: start, size
    logical, intent(in) :: exact
    integer(int64) :: used
    used = w%pos - start
    if (size < 0 .or. size > shiftr(huge(size), 3)) then
      call pb_fail(w, PB_RANGE, 'the content takes ' // pb_itoa(used) // ' bit(s), more than its size of ' // &
        pb_itoa(size) // ' byte(s)')
      return
    end if
    if (used > size * 8) then
      call pb_fail(w, PB_RANGE, 'the content takes ' // pb_itoa(used) // ' bit(s), more than its size of ' // &
        pb_itoa(size) // ' byte(s)')
      return
    end if
    if (exact .and. used /= size * 8) then
      call pb_fail(w, PB_MISMATCH, 'the content takes ' // pb_itoa(used) // ' bit(s) but must fill its ' // &
        pb_itoa(size) // ' byte(s)')
      return
    end if
    call pb_write_zero_bits(w, size * 8 - used)
  end subroutine pb_end_window

  !> Overwrite NBYTES bytes at bit position AT (byte aligned).
  pure subroutine pb_patch_uint(w, at, value, nbytes, little)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: at, value
    integer, intent(in) :: nbytes
    logical, intent(in) :: little
    integer :: i, shift
    do i = 0, nbytes - 1
      if (little) then
        shift = 8 * i
      else
        shift = 8 * (nbytes - 1 - i)
      end if
      w%buf(at / 8 + i) = pb_i8(shiftr(value, shift))
    end do
  end subroutine pb_patch_uint

  !> Overwrite WIDTH bits at bit position AT, MSB first.
  pure subroutine pb_patch_bits(w, at, value, width)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: at, value
    integer, intent(in) :: width
    integer :: i, off
    integer(int64) :: b, cur
    do i = 0, width - 1
      b = (at + i) / 8
      off = 7 - int(mod(at + i, 8_int64))
      cur = pb_u8(w%buf(b))
      if (btest(value, width - 1 - i)) then
        cur = ibset(cur, off)
      else
        cur = ibclr(cur, off)
      end if
      w%buf(b) = pb_i8(cur)
    end do
  end subroutine pb_patch_bits

  !> Checksum ALGO of the output between two bit positions (whole bytes);
  !> the bytes between HOLE_FROM and HOLE_TO count as zero.
  pure function pb_writer_checksum(w, algo, from, to, hole_from, hole_to) result(v)
    type(pb_writer), intent(in) :: w
    integer, intent(in) :: algo
    integer(int64), intent(in) :: from, to, hole_from, hole_to
    integer(int64) :: v
    v = pb_checksum(algo, w%buf, from / 8, to / 8, hole_from / 8, hole_to / 8)
  end function pb_writer_checksum

  !> The bytes of a string (UTF-8) in encoding ENC (see pb_decode_text).
  pure subroutine pb_text_bytes(w, s, enc, out)
    type(pb_writer), intent(inout) :: w
    character(len=:), allocatable, intent(in) :: s
    integer, intent(in) :: enc
    integer(int8), allocatable, intent(out) :: out(:)
    integer(int8), allocatable :: raw(:)
    integer(int32), allocatable :: cps(:)
    integer(int64) :: n, i, ncp, c, k, hi, lo
    logical :: ok
    character(len=8) :: name
    n = pb_strlen(s)
    allocate(raw(n))
    do i = 1, n
      raw(i) = pb_i8(int(ichar(s(i:i)), int64))
    end do
    call pb_utf8_points(raw, n, cps, ncp, ok)
    if (.not. ok) then
      call pb_fail(w, PB_TEXT, 'the string is not valid Unicode (invalid UTF-8)')
      allocate(out(0))
      return
    end if
    if (enc == 0) then
      call move_alloc(raw, out)
      return
    end if
    select case (enc)
    case (1)
      name = 'ASCII'
    case (2)
      name = 'Latin-1'
    case default
      name = 'UTF-16'
    end select
    if (enc >= 3) then
      allocate(out(4 * ncp))
    else
      allocate(out(ncp))
    end if
    k = 0
    do i = 1, ncp
      c = cps(i)
      if ((enc == 1 .and. c > 127) .or. (enc == 2 .and. c > 255)) then
        call pb_fail(w, PB_TEXT, 'the string is not valid ' // trim(name))
        out = out(1:0)
        return
      end if
      if (enc < 3) then
        k = k + 1
        out(k) = pb_i8(c)
      else if (c < 65536) then
        call pb_put_unit(out, k, c, enc)
      else
        hi = 55296 + shiftr(c - 65536, 10)
        lo = 56320 + iand(c - 65536, 1023_int64)
        call pb_put_unit(out, k, hi, enc)
        call pb_put_unit(out, k, lo, enc)
      end if
    end do
    out = out(1:k)
  end subroutine pb_text_bytes

  pure subroutine pb_put_unit(out, k, u, enc)
    integer(int8), intent(inout) :: out(:)
    integer(int64), intent(inout) :: k
    integer(int64), intent(in) :: u
    integer, intent(in) :: enc
    if (enc == 3) then
      out(k + 1) = pb_i8(u)
      out(k + 2) = pb_i8(shiftr(u, 8))
    else
      out(k + 1) = pb_i8(shiftr(u, 8))
      out(k + 2) = pb_i8(u)
    end if
    k = k + 2
  end subroutine pb_put_unit

  !> One variable-length integer (see pb_read_varint).
  pure subroutine pb_write_varint(w, kind, value)
    type(pb_writer), intent(inout) :: w
    integer, intent(in) :: kind
    integer(int64), intent(in) :: value
    integer(int64) :: v, x, b, groups(10)
    logical :: done
    integer :: n, i
    v = value
    select case (kind)
    case (5)
      if (v >= 0 .and. v < 128) then
        call pb_write_uint(w, v, 1, .false.)
      else if (v >= 0 .and. v <= 32767) then
        call pb_write_uint(w, ior(v, 32768_int64), 2, .false.)
      else
        call pb_fail(w, PB_RANGE, pb_utoa(v) // ' does not fit in a varint15')
      end if
    case (4)
      if (v >= 0 .and. v <= 63) then
        call pb_write_uint(w, v, 1, .false.)
      else if (v >= 0 .and. v <= 16383) then
        call pb_write_uint(w, ior(v, ishft(1_int64, 14)), 2, .false.)
      else if (v >= 0 .and. v <= 1073741823_int64) then
        call pb_write_uint(w, ior(v, ishft(2_int64, 30)), 4, .false.)
      else if (v >= 0 .and. v <= 4611686018427387903_int64) then
        call pb_write_uint(w, ior(v, ishft(3_int64, 62)), 8, .false.)
      else
        call pb_fail(w, PB_RANGE, pb_utoa(v) // ' does not fit in a QUIC varint')
      end if
    case (1)
      x = v
      do
        b = iand(x, 127_int64)
        x = shifta(x, 7)
        done = (x == 0 .and. iand(b, 64_int64) == 0) .or. (x == -1 .and. iand(b, 64_int64) /= 0)
        if (done) then
          call pb_write_uint(w, b, 1, .false.)
          exit
        end if
        call pb_write_uint(w, ior(b, 128_int64), 1, .false.)
      end do
    case (3)
      groups(1) = iand(v, 127_int64)
      n = 1
      v = shiftr(v, 7)
      do while (v /= 0)
        n = n + 1
        groups(n) = ior(iand(v, 127_int64), 128_int64)
        v = shiftr(v, 7)
      end do
      do i = n, 1, -1
        call pb_write_uint(w, groups(i), 1, .false.)
      end do
    case default
      if (kind == 2) v = ieor(ishft(v, 1), shifta(v, 63))
      do
        b = iand(v, 127_int64)
        v = shiftr(v, 7)
        if (v /= 0) then
          call pb_write_uint(w, ior(b, 128_int64), 1, .false.)
        else
          call pb_write_uint(w, b, 1, .false.)
          exit
        end if
      end do
    end select
  end subroutine pb_write_varint

  pure subroutine pb_check_no_term(w, data, term)
    type(pb_writer), intent(inout) :: w
    integer(int8), allocatable, intent(in) :: data(:)
    integer(int8), intent(in) :: term(:)
    integer(int64) :: i, nt, n
    if (.not. allocated(data)) return
    n = size(data, kind=int64)
    nt = size(term, kind=int64)
    i = 1
    do while (i + nt - 1 <= n)
      if (all(data(i:i + nt - 1) == term)) then
        call pb_fail(w, PB_INVALID, 'the value contains its terminator')
        return
      end if
      i = i + 1
    end do
  end subroutine pb_check_no_term

  pure subroutine pb_check_fits(w, length, size)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: length, size
    if (length > size) call pb_fail(w, PB_RANGE, pb_itoa(length) // ' byte(s) do not fit in ' // pb_itoa(size))
  end subroutine pb_check_fits

  pure subroutine pb_check_no_nul(w, data)
    type(pb_writer), intent(inout) :: w
    integer(int8), allocatable, intent(in) :: data(:)
    if (.not. allocated(data)) return
    if (any(data == 0)) call pb_fail(w, PB_TEXT, 'the string contains a NUL byte')
  end subroutine pb_check_no_nul

  pure subroutine pb_check_len(w, actual, expected)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: actual, expected
    if (actual /= expected) then
      call pb_fail(w, PB_MISMATCH, pb_itoa(actual) // ' element(s) but the length expression says ' // pb_itoa(expected))
    end if
  end subroutine pb_check_len

  !> Fail unless the bits of V (unsigned) fit in WIDTH bits.
  pure subroutine pb_check_u(w, v, width)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: v
    integer, intent(in) :: width
    if (width >= 64) return
    if (shiftr(v, width) /= 0) then
      call pb_fail(w, PB_RANGE, 'value ' // pb_utoa(v) // ' does not fit in ' // pb_itoa(int(width, int64)) // ' bit(s)')
    end if
  end subroutine pb_check_u

  !> Fail unless V fits in WIDTH signed bits.
  pure subroutine pb_check_i(w, v, width)
    type(pb_writer), intent(inout) :: w
    integer(int64), intent(in) :: v
    integer, intent(in) :: width
    if (width >= 64) return
    if (v < -ishft(1_int64, width - 1) .or. v > ishft(1_int64, width - 1) - 1) then
      call pb_fail(w, PB_RANGE, 'value ' // pb_itoa(v) // ' does not fit in ' // pb_itoa(int(width, int64)) // &
        ' signed bit(s)')
    end if
  end subroutine pb_check_i

  ! -- arithmetic: integers are int64 and wrap; nothing traps

  elemental function pb_add(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    if (a > 0 .and. b > huge(a) - a) then
      r = (a - huge(a) - 1) + (b - huge(a) - 1)
    else if (a < 0 .and. b < PB_MIN64 - a) then
      r = (a + huge(a) + 1) + (b + huge(a) + 1)
    else
      r = a + b
    end if
  end function pb_add

  elemental function pb_subt(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    if (b /= PB_MIN64) then
      r = pb_add(a, -b)
    else if (a >= 0) then
      r = a + b
    else
      r = a - b
    end if
  end function pb_subt

  elemental function pb_neg(a) result(r)
    integer(int64), intent(in) :: a
    integer(int64) :: r
    if (a == PB_MIN64) then
      r = a
    else
      r = -a
    end if
  end function pb_neg

  elemental function pb_mul(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    integer(int64), parameter :: lim = 2147483647_int64
    integer(int64) :: x(0:3), y(0:3), s, c
    integer :: i, k
    if (a >= -lim .and. a <= lim .and. b >= -lim .and. b <= lim) then
      r = a * b
      return
    end if
    do i = 0, 3
      x(i) = ibits(a, 16 * i, 16)
      y(i) = ibits(b, 16 * i, 16)
    end do
    r = 0
    c = 0
    do k = 0, 3
      s = c
      do i = 0, k
        s = s + x(i) * y(k - i)
      end do
      r = ior(r, ishft(iand(s, 65535_int64), 16 * k))
      c = shiftr(s, 16)
    end do
  end function pb_mul

  elemental function pb_div(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    if (b == 0) then
      r = 0
    else if (b == -1) then
      r = pb_neg(a)
    else
      r = a / b
    end if
  end function pb_div

  elemental function pb_mod(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    if (b == 0 .or. b == -1) then
      r = 0
    else
      r = mod(a, b)
    end if
  end function pb_mod

  elemental function pb_shl(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    if (b < 0 .or. b > 63) then
      r = 0
    else
      r = ishft(a, int(b))
    end if
  end function pb_shl

  !> Arithmetic shift right.
  elemental function pb_shr(a, b) result(r)
    integer(int64), intent(in) :: a, b
    integer(int64) :: r
    if (b < 0) then
      r = 0
    else
      r = shifta(a, int(min(b, 63_int64)))
    end if
  end function pb_shr

  elemental function pb_pow(base, e) result(r)
    integer(int64), intent(in) :: base, e
    integer(int64) :: r
    integer(int64) :: b, x
    r = 0
    if (e < 0) return
    r = 1
    b = base
    x = e
    do while (x > 0)
      if (iand(x, 1_int64) == 1) r = pb_mul(r, b)
      b = pb_mul(b, b)
      x = shiftr(x, 1)
    end do
  end function pb_pow

  elemental function pb_powf(b, e) result(r)
    real(real64), intent(in) :: b, e
    real(real64) :: r
    r = b ** e
  end function pb_powf

  elemental function pb_fdiv(a, b) result(r)
    real(real64), intent(in) :: a, b
    real(real64) :: r
    r = a / b
  end function pb_fdiv

  !> Float to integer: truncated, NaN as 0, clamped to the int64 range.
  elemental function pb_ftoi(v) result(r)
    real(real64), intent(in) :: v
    integer(int64) :: r
    if (ieee_is_nan(v)) then
      r = 0
    else if (v >= 9.223372036854775807e18_real64) then
      r = huge(r)
    else if (v <= -9.223372036854775808e18_real64) then
      r = PB_MIN64
    else
      r = int(v, int64)
    end if
  end function pb_ftoi

  elemental function pb_minf(a, b) result(r)
    real(real64), intent(in) :: a, b
    real(real64) :: r
    if (ieee_is_nan(a)) then
      r = b
    else if (ieee_is_nan(b)) then
      r = a
    else if (a < b) then
      r = a
    else
      r = b
    end if
  end function pb_minf

  elemental function pb_maxf(a, b) result(r)
    real(real64), intent(in) :: a, b
    real(real64) :: r
    if (ieee_is_nan(a)) then
      r = b
    else if (ieee_is_nan(b)) then
      r = a
    else if (a > b) then
      r = a
    else
      r = b
    end if
  end function pb_maxf

  elemental function pb_sqrt(v) result(r)
    real(real64), intent(in) :: v
    real(real64) :: r
    if (ieee_is_nan(v) .or. v < 0) then
      r = ieee_value(r, ieee_quiet_nan)
    else
      r = sqrt(v)
    end if
  end function pb_sqrt

  !> Padding needed after OFFSET bits to reach a multiple of UNITS bits.
  elemental function pb_pad(offset, units) result(r)
    integer(int64), intent(in) :: offset, units
    integer(int64) :: r
    r = mod(units - mod(offset, units), units)
  end function pb_pad

  !> The low WIDTH bits of V, sign-extended.
  elemental function pb_sext(v, width) result(r)
    integer(int64), intent(in) :: v
    integer, intent(in) :: width
    integer(int64) :: r
    r = v
    if (width < 64) then
      if (btest(v, width - 1)) r = ior(v, ishft(-1_int64, width))
    end if
  end function pb_sext

  !> V cut to WIDTH bits, as a signed or unsigned value.
  elemental function pb_trunc(v, width, signed) result(r)
    integer(int64), intent(in) :: v
    integer, intent(in) :: width
    logical, intent(in) :: signed
    integer(int64) :: r
    if (width >= 64) then
      r = v
      return
    end if
    r = iand(v, maskr(width, int64))
    if (signed) r = pb_sext(r, width)
  end function pb_trunc

  ! -- float bit patterns

  elemental function pb_bits_f32(v) result(r)
    integer(int64), intent(in) :: v
    real(real32) :: r
    r = transfer(int(pb_trunc(v, 32, .true.), int32), r)
  end function pb_bits_f32

  elemental function pb_f32_bits(v) result(r)
    real(real32), intent(in) :: v
    integer(int64) :: r
    r = iand(int(transfer(v, 0_int32), int64), maskr(32, int64))
  end function pb_f32_bits

  elemental function pb_bits_f64(v) result(r)
    integer(int64), intent(in) :: v
    real(real64) :: r
    r = transfer(v, r)
  end function pb_bits_f64

  elemental function pb_f64_bits(v) result(r)
    real(real64), intent(in) :: v
    integer(int64) :: r
    r = transfer(v, r)
  end function pb_f64_bits

  ! -- arrays

  pure function pb_elem_u8(a, i) result(v)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    integer(int64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = pb_u8(a(i + 1))
  end function pb_elem_u8

  pure function pb_elem_i8(a, i) result(v)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    integer(int64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = int(a(i + 1), int64)
  end function pb_elem_i8

  pure function pb_elem_i16(a, i) result(v)
    integer(int16), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    integer(int64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = int(a(i + 1), int64)
  end function pb_elem_i16

  pure function pb_elem_i32(a, i) result(v)
    integer(int32), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    integer(int64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = int(a(i + 1), int64)
  end function pb_elem_i32

  pure function pb_elem_i64(a, i) result(v)
    integer(int64), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    integer(int64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = a(i + 1)
  end function pb_elem_i64

  pure function pb_elem_r32(a, i) result(v)
    real(real32), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    real(real64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = real(a(i + 1), real64)
  end function pb_elem_r32

  pure function pb_elem_r64(a, i) result(v)
    real(real64), allocatable, intent(in) :: a(:)
    integer(int64), intent(in) :: i
    real(real64) :: v
    v = 0
    if (.not. allocated(a)) return
    if (i >= 0 .and. i < size(a, kind=int64)) v = a(i + 1)
  end function pb_elem_r64

  pure function pb_sum_u8(a) result(v)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_add(v, pb_u8(a(i)))
    end do
  end function pb_sum_u8

  pure function pb_sum_i8(a) result(v)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_add(v, int(a(i), int64))
    end do
  end function pb_sum_i8

  pure function pb_sum_i16(a) result(v)
    integer(int16), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_add(v, int(a(i), int64))
    end do
  end function pb_sum_i16

  pure function pb_sum_i32(a) result(v)
    integer(int32), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_add(v, int(a(i), int64))
    end do
  end function pb_sum_i32

  pure function pb_sum_i64(a) result(v)
    integer(int64), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_add(v, a(i))
    end do
  end function pb_sum_i64

  pure function pb_sum_r32(a) result(v)
    real(real32), allocatable, intent(in) :: a(:)
    real(real64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = v + real(a(i), real64)
    end do
  end function pb_sum_r32

  pure function pb_sum_r64(a) result(v)
    real(real64), allocatable, intent(in) :: a(:)
    real(real64) :: v
    integer(int64) :: i
    v = 0
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = v + a(i)
    end do
  end function pb_sum_r64

  pure function pb_product_u8(a) result(v)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_mul(v, pb_u8(a(i)))
    end do
  end function pb_product_u8

  pure function pb_product_i8(a) result(v)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_mul(v, int(a(i), int64))
    end do
  end function pb_product_i8

  pure function pb_product_i16(a) result(v)
    integer(int16), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_mul(v, int(a(i), int64))
    end do
  end function pb_product_i16

  pure function pb_product_i32(a) result(v)
    integer(int32), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_mul(v, int(a(i), int64))
    end do
  end function pb_product_i32

  pure function pb_product_i64(a) result(v)
    integer(int64), allocatable, intent(in) :: a(:)
    integer(int64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = pb_mul(v, a(i))
    end do
  end function pb_product_i64

  pure function pb_product_r32(a) result(v)
    real(real32), allocatable, intent(in) :: a(:)
    real(real64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = v * real(a(i), real64)
    end do
  end function pb_product_r32

  pure function pb_product_r64(a) result(v)
    real(real64), allocatable, intent(in) :: a(:)
    real(real64) :: v
    integer(int64) :: i
    v = 1
    if (.not. allocated(a)) return
    do i = 1, size(a, kind=int64)
      v = v * a(i)
    end do
  end function pb_product_r64

  pure function pb_size_i8(a) result(n)
    integer(int8), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_i8

  pure function pb_size_i16(a) result(n)
    integer(int16), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_i16

  pure function pb_size_i32(a) result(n)
    integer(int32), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_i32

  pure function pb_size_i64(a) result(n)
    integer(int64), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_i64

  pure function pb_size_r32(a) result(n)
    real(real32), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_r32

  pure function pb_size_r64(a) result(n)
    real(real64), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_r64

  pure function pb_size_mac(a) result(n)
    type(pb_mac), allocatable, intent(in) :: a(:)
    integer(int64) :: n
    n = 0
    if (allocated(a)) n = size(a, kind=int64)
  end function pb_size_mac

  ! -- checksums

  !> Checksum ALGO of BUF(FROM:TO-1) with BUF(HOLE_FROM:HOLE_TO-1) as zeros
  !> (0-based; algorithm numbers as in the other runtimes).
  pure function pb_checksum(algo, buf, from, to, hole_from, hole_to) result(v)
    integer, intent(in) :: algo
    integer(int8), allocatable, intent(in) :: buf(:)
    integer(int64), intent(in) :: from, to, hole_from, hole_to
    integer(int64) :: v
    integer(int64), parameter :: polys(0:7) = [7_int64, 40961_int64, 4129_int64, 4129_int64, 33800_int64, &
      40961_int64, 3988292384_int64, 2197175160_int64]
    integer(int64), parameter :: inits(0:7) = [0_int64, 0_int64, 65535_int64, 0_int64, 0_int64, 65535_int64, &
      4294967295_int64, 4294967295_int64]
    integer, parameter :: widths(0:7) = [8, 16, 16, 16, 16, 16, 32, 32]
    logical, parameter :: reflected(0:7) = [.false., .true., .false., .false., .true., .true., .true., .true.]
    integer(int64) :: i, x, a, b, mask, crc, lb
    integer :: k, width
    v = 0
    if (.not. allocated(buf)) return
    lb = lbound(buf, 1, kind=int64)
    if (algo < 8) then
      width = widths(algo)
      mask = maskr(width, int64)
      crc = inits(algo)
      do i = from, to - 1
        x = 0
        if (i < hole_from .or. i >= hole_to) x = pb_u8(buf(lb + i))
        if (reflected(algo)) then
          crc = ieor(crc, x)
          do k = 1, 8
            if (iand(crc, 1_int64) /= 0) then
              crc = ieor(shiftr(crc, 1), polys(algo))
            else
              crc = shiftr(crc, 1)
            end if
          end do
        else
          crc = ieor(crc, ishft(x, width - 8))
          do k = 1, 8
            if (btest(crc, width - 1)) then
              crc = iand(ieor(ishft(crc, 1), polys(algo)), mask)
            else
              crc = iand(ishft(crc, 1), mask)
            end if
          end do
        end if
      end do
      if (algo >= 6) crc = ieor(crc, 4294967295_int64)
      v = iand(crc, mask)
      return
    end if
    a = 0
    b = 0
    do i = from, to - 1
      x = 0
      if (i < hole_from .or. i >= hole_to) x = pb_u8(buf(lb + i))
      select case (algo)
      case (8)
        if (mod(i - from, 2_int64) == 0) then
          a = a + ishft(x, 8)
        else
          a = a + x
        end if
      case (9)
        a = mod(a + x, 255_int64)
        b = mod(b + a, 255_int64)
      case (10)
        a = iand(a + x, 255_int64)
      case (12)
        a = iand(a + x, 65535_int64)
      case (13)
        a = iand(a + ishft(x, int(8 * (3 - mod(i - from, 4_int64)))), 4294967295_int64)
      case default
        a = ieor(a, x)
      end select
    end do
    if (algo == 8) then
      do while (shiftr(a, 16) /= 0)
        a = iand(a, 65535_int64) + shiftr(a, 16)
      end do
      v = iand(not(a), 65535_int64)
    else if (algo == 13) then
      v = iand(shiftr(a, 16) + iand(a, 65535_int64), 65535_int64)
    else if (algo == 9) then
      v = ior(ishft(b, 8), a)
    else
      v = a
    end if
  end function pb_checksum

  ! -- JSON (for to_json)

  pure subroutine pb_sb_add(sb, s)
    type(pb_sb), intent(inout) :: sb
    character(len=*), intent(in) :: s
    character(len=:), allocatable :: t
    integer :: cap
    if (.not. allocated(sb%s)) allocate(character(len=max(256, len(s))) :: sb%s)
    if (sb%n + len(s) > len(sb%s)) then
      cap = max(sb%n + len(s), 2 * len(sb%s))
      allocate(character(len=cap) :: t)
      t(1:sb%n) = sb%s(1:sb%n)
      call move_alloc(t, sb%s)
    end if
    sb%s(sb%n + 1:sb%n + len(s)) = s
    sb%n = sb%n + len(s)
  end subroutine pb_sb_add

  pure function pb_sb_text(sb) result(s)
    type(pb_sb), intent(in) :: sb
    character(len=:), allocatable :: s
    if (allocated(sb%s)) then
      s = sb%s(1:sb%n)
    else
      s = ''
    end if
  end function pb_sb_text

  pure subroutine pb_json_i(sb, v)
    type(pb_sb), intent(inout) :: sb
    integer(int64), intent(in) :: v
    call pb_sb_add(sb, pb_itoa(v))
  end subroutine pb_json_i

  !> The bits of V as an unsigned number.
  pure subroutine pb_json_u(sb, v)
    type(pb_sb), intent(inout) :: sb
    integer(int64), intent(in) :: v
    call pb_sb_add(sb, pb_utoa(v))
  end subroutine pb_json_u

  !> A number with 17 significant digits; NaN and infinities as null.
  subroutine pb_json_f(sb, v)
    type(pb_sb), intent(inout) :: sb
    real(real64), intent(in) :: v
    character(len=32) :: buf
    if (ieee_is_nan(v) .or. abs(v) > huge(v)) then
      call pb_sb_add(sb, 'null')
      return
    end if
    write(buf, '(es25.16e3)') v
    call pb_sb_add(sb, trim(adjustl(buf)))
  end subroutine pb_json_f

  !> Bytes as a JSON string of hex digits.
  pure subroutine pb_json_bytes(sb, b)
    type(pb_sb), intent(inout) :: sb
    integer(int8), intent(in) :: b(:)
    character(len=16), parameter :: digits = '0123456789abcdef'
    character(len=:), allocatable :: t
    integer :: i, x
    allocate(character(len=2 * size(b) + 2) :: t)
    t(1:1) = '"'
    do i = 1, size(b)
      x = int(pb_u8(b(i)))
      t(2 * i:2 * i) = digits(x / 16 + 1:x / 16 + 1)
      t(2 * i + 1:2 * i + 1) = digits(mod(x, 16) + 1:mod(x, 16) + 1)
    end do
    t(len(t):len(t)) = '"'
    call pb_sb_add(sb, t)
  end subroutine pb_json_bytes

  pure subroutine pb_json_hex(sb, b)
    type(pb_sb), intent(inout) :: sb
    integer(int8), allocatable, intent(in) :: b(:)
    if (allocated(b)) then
      call pb_json_bytes(sb, b)
    else
      call pb_sb_add(sb, '""')
    end if
  end subroutine pb_json_hex

  !> A JSON string literal; the text is UTF-8 and kept as it is.
  pure subroutine pb_json_text(sb, s)
    type(pb_sb), intent(inout) :: sb
    character(len=*), intent(in) :: s
    character(len=16), parameter :: digits = '0123456789abcdef'
    integer :: i, c
    call pb_sb_add(sb, '"')
    do i = 1, len(s)
      c = ichar(s(i:i))
      if (c == 34) then
        call pb_sb_add(sb, '\"')
      else if (c == 92) then
        call pb_sb_add(sb, '\\')
      else if (c < 32 .or. c == 127) then
        call pb_sb_add(sb, '\u00' // digits(c / 16 + 1:c / 16 + 1) // digits(mod(c, 16) + 1:mod(c, 16) + 1))
      else
        call pb_sb_add(sb, s(i:i))
      end if
    end do
    call pb_sb_add(sb, '"')
  end subroutine pb_json_text

  pure subroutine pb_json_str(sb, s)
    type(pb_sb), intent(inout) :: sb
    character(len=:), allocatable, intent(in) :: s
    if (allocated(s)) then
      call pb_json_text(sb, s)
    else
      call pb_sb_add(sb, '""')
    end if
  end subroutine pb_json_str

  ! ---- generated procedures -----------------------------------------------
