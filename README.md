# packet-builder

A small language for describing binary packets, similar to Protocol Buffers but
aimed at *existing* wire formats: you describe the bytes (and bits) a protocol
already uses, and packet-builder generates a decoder and encoder for

| language | output | toolchain used by the tests |
|----------|--------|-----------------------------|
| C        | single-header library (`<package>.h`, C99) | `cc` with ASan + UBSan |
| Rust     | one module (`<package>.rs`), no dependencies | `rustc` |
| Go       | one file (`<package>.go`), standard library only (Go 1.18+) | `go vet`, `gofmt`, `go build` |
| Python   | one module (`<package>.py`), standard library only | `python3` |
| C#       | one file (`<package>.cs`), base class library only | `dotnet` / `csc` |
| Zig      | one file (`<package>.zig`, Zig 0.13) | `zig build-exe` with a leak-checking allocator |

```
packet Flap be {
  start uint8,
  channel uint8,
  sequence uint16,
  length uint16,
  payload bytes[length],
  calc valid uint8 = start == 0x2a and channel >= 1 and channel <= 5
}

packet Ipv4 be {
  version u4, ihl u4, dscp u6, ecn u2,
  total_length uint16,
  identification uint16,
  _ u1, dont_fragment u1, more_fragments u1, fragment_offset u13,
  ttl uint8, protocol uint8, checksum uint16,
  source uint8[4], destination uint8[4],
  options bytes[ihl * 4 - 20]
}
```

Real protocol descriptions live in [`examples/`](examples):

* [`examples/oscar.packet`](examples/oscar.packet): **OSCAR**, the AIM/ICQ
  protocol (FLAP framing, SNAC headers with their flag bits, TLV chains,
  instant messages, rate limits). [`docs/oscar.md`](docs/oscar.md) walks through
  decoding a captured AIM session and sending a reply.
* [`examples/p3.packet`](examples/p3.packet): **P3**, the link protocol of
  the original AOL client (framing with a bitfield type byte, INIT, DATA
  packets with tokens, FDO91 atom streams).
  [`docs/p3.md`](docs/p3.md) decodes a session that includes a captured INIT
  packet, checks the CRCs and builds a reply.
* [`examples/network.packet`](examples/network.packet): Ethernet, IPv4, TCP,
  UDP and DNS headers, all heavy users of sub-byte fields.

## Usage

```sh
cargo run -- generate examples/oscar.packet -o out            # every language, files named oscar.*
cargo run -- gen examples/oscar.packet -l rust,go -o out       # a subset (`gen` is short for `generate`)
cargo run -- gen examples/oscar.packet -p aim -o out           # file stem / Go package / C# namespace
cargo run -- gen examples/oscar.packet -l python --stdout      # print instead of writing files
cargo run -- check examples/*.packet                   # validate only
cargo run -- layout tests/specs/types.packet -k CStruct
cargo run -- decode examples/oscar.packet -k Flap --hex "2a01 1f3a 0004 00000001"
cargo run -- decode examples/oscar.packet -k Flap --all --hex "..."   # frames back to back
cargo run -- decode examples/oscar.packet -k Flap --pcap capture.pcapng --offset 54 --json
cargo run -- languages
cargo run -- --help
```

`layout` prints where every field ends up, including padding inserted by
alignment:

```
packet CStruct: 32 byte(s), alignment 8
    offset    size  field                    type
         0       1  a                        u8
         1       3  _                        padding to 4 byte(s)
         4       4  b                        u32
         8       2  c                        u16
        10       6  _                        padding to 8 byte(s)
        16       8  d                        u64
        24       1  e                        u8
        25       7  _                        padding to 8 byte(s)
```

Errors are reported with the offending source location:

```
Error: uint16 `b` starts 3 bit(s) into a byte; standard integer types must be byte aligned
   ╭─[bad.packet:1:18]
 1 │ packet P { a u3, b uint16 }
   │                  ────┬────
   │                      ╰────── uint16 `b` starts 3 bit(s) into a byte; ...
   │ Note: use a uN type for integers that live in the bit stream, or add `_ uN` padding before this field
```

`decode` runs a description directly, without generating code, and prints
what each field holds (category names included), or where decoding stopped:

```
$ cargo run -- decode examples/oscar.packet -k Flap --hex "2a01 1f3a 0004 00000001"
Flap
  start: 42 (0x2a)
  channel: 1 (Channel.signon)
  sequence: 7994 (0x1f3a)
  length: 4
  payload: 00000001 (4 bytes)
  valid (calculated): 1
```

Input comes from `--hex`, a raw `--file`, or a `--pcap` capture (pcap or
pcapng; every frame is decoded). `--offset` skips lower-layer headers.

The crate is also a library: `packet_builder::generate(source, Language::Go, &GenOptions::default())`,
and `packet_builder::ir::interp::{decode, encode}` decode and encode with a
compiled module directly.

## Language reference

A file contains one or more packets. A packet has an optional default byte
order (`le` or `be`; little-endian if omitted) and a comma-separated list of
fields. `//` starts a comment.

### Types

| type | meaning |
|------|---------|
| `uint8` `uint16` `uint32` `uint64`, `int8` ... `int64` | byte-aligned integers in the packet's (or field's) byte order |
| `u1` ... `u64`, `i2` ... `i64` | **integers of any bit width**, read most-significant-bit first from the bit stream, with no alignment requirement |
| `float32` `float64` | IEEE 754, byte aligned |
| `macaddress` | 6 bytes |
| `datetime` | 64-bit signed integer |
| `bytes` | a byte buffer (always used with a length, or as the last field) |
| `char[n]`, `string[n]`, `string(uint8)`, `cstring` | text, see [Strings](#strings) |
| `OtherPacket` | another packet from the same file, decoded in place |

C and assembly-style names are aliases for the types above:

| alias | same as |
|-------|---------|
| `char` (single) | `uint8` (`char[n]` is a string) |
| `unsigned char`, `uchar`, `byte` | `uint8` |
| `short` / `unsigned short`, `ushort` | `int16` / `uint16` |
| `int` / `unsigned int`, `uint` | `int32` / `uint32` |
| `half word`, `halfword` | half a word, unsigned |
| `word` | one word, unsigned |
| `double word`, `doubleword`, `dword` | two words, unsigned |
| `quad word`, `quadword`, `qword` | four words, unsigned |

A word is 16 bits by default (x86 naming: half word 8, word 16, double word
32, quad word 64). Start a file with `wordsize 32` for ARM-style naming (half
word 16, word 32, double word 64); a quad word would then be 128 bits, so it
is rejected. Type names are not reserved: a field may be called `word` or
`string`.

A field may override the byte order: `b uint16 le`. A `uN` whose width is a
multiple of 8 and that starts on a byte boundary also honours the byte order,
which is how you write a 24-bit little-endian integer: `x u24 le`.

### Bit fields

There are two ways to split bytes into bits.

**Bit-stream fields.** `uN` / `iN` fields follow each other bit by bit and can
cross byte boundaries freely:

```
packet BitStream be { a u3, b u7, c i6, d u13, e u35, _ u4 }
```

**Bitfield containers.** A `bitfield` reads one integer (with its byte order)
and splits it into named members. Bits that no member covers are padding:

```
packet Flags8 {
  flags bitfield uint8 {
    one u1,     // bit 7 (0x80)
    two u2,     // bits 6..5
    three u3    // bits 4..2; bits 1..0 are padding
  }
}
```

* Members are taken from the most significant bit by default; write
  `bitfield uint16 le lsb { ... }` to start from the least significant bit
  (the layout C compilers use on x86).
* The container can be any integer type, including a `uN`: TCP's nine flag
  bits are `flags bitfield u9 { ns u1, cwr u1, ... fin u1 }`.
* Signed members (`delta i5`) are sign-extended.
* Members become ordinary fields of the packet (`p.one`, `p.two`, ...).

**Padding.** A field or member named `_` is not stored. It is skipped when
decoding and written as zeros when encoding: `_ u3`, `_ uint16`, `_ bytes[n]`.

**Alignment rules** are checked at compile time. Standard integer types,
floats, MAC addresses, byte buffers and nested packets must start on a byte
boundary, and every packet must be a whole number of bytes. The checker tracks
variable-length arrays too: `u12[n * 2]` is always a whole number of bytes,
while `u12[n]` might not be.

### Strings

Strings hold UTF-8 text. Invalid UTF-8 (including overlong forms and
surrogates) is a decode error in every language, and strings that don't fit
are encode errors.

| syntax | on the wire | decode | encode |
|--------|-------------|--------|--------|
| `name char[16]` | exactly 16 bytes (the count may be any expression) | text up to the first NUL | NUL-padded to 16 bytes; error if longer |
| `name string[len]` | exactly `len` bytes | all of them | length must equal `len` |
| `name string(uint8)` | a length (any unsigned integer type, e.g. `string(uint16 le)`), then the bytes | | the length is written from the string; error if it doesn't fit |
| `name cstring` | bytes up to a NUL terminator | error if there's no terminator | NUL appended; error if the text contains NUL |
| `name string`, `name string[]` | the rest of the input (last field only) | | |

```
packet Login be {
  user char[16],
  password_length uint8,
  password string[password_length],
  client string(uint16),
  motd cstring
}
```

### Alignment

Alignment is in bytes and counted from the start of the packet. The padding
is skipped when decoding and written as zeros when encoding. If the offset
depends on the data, the padding is computed at run time.

* `b uint32 align 4`: pad before this field to a multiple of 4.
* `align 8` on its own line inside a packet: pad to a multiple of 8 at that point.
* `packet P le align 8 { ... }`: lay the packet out like a C struct compiled
  with `#pragma pack(8)`. Each field is aligned to the smaller of its natural
  alignment and 8, and the packet is padded to a multiple of its own
  alignment. Nested packets use their alignment, so arrays of them match C
  arrays of structs.

Without any `align`, nothing is padded and fields follow each other exactly
(including bit fields).

### Arrays

| syntax | meaning |
|--------|---------|
| `x uint16[4]` | fixed count |
| `x uint16[count]`, `x bytes[length - 10]` | count from any integer expression over earlier fields |
| `x Tlv[]`, `x bytes[]`, `x bytes` | repeat until the input ends (last field only); a trailing partial element is an error |
| `x Opt[flag]` | an optional field: a count of 0 or 1 taken from a flag |

`uint8` arrays and `bytes` are byte buffers in every language. Strings are
native strings (`String`, `string`, `str`; `[]const u8` in Zig; in C a
NUL-terminated `char *` plus a `_len` member). Lengths are
validated before anything is allocated: a negative length, or one larger than
the remaining input, is a decode error. When encoding, an array whose length
does not match its length expression is an encode error.

### Calculated fields

```
calc header_length uint8 = ihl * 4,
calc valid uint8 = start == 0x2a and channel >= 1,
calc warning_percent float64 = warning_level / 10.0
```

Calculated fields are computed after decoding and stored in the struct. They
are not written when encoding. They may be used in array lengths (also before
their own declaration), and are evaluated as soon as their inputs are known.

### Constants

Name a protocol's magic numbers instead of leaving them in comments. A
`const` declaration sits at file level, next to the packets:

```
const FLAP_START uint8 = 0x2a "first byte of every frame"

const Channel uint8 {               // a category of related values
  signon = 1   "sign-on",
  snac = 2     "SNAC data",
  keep_alive = 5,
}

packet Flap be {
  start uint8,
  channel uint8 : Channel,          // this field's values come from Channel
  length uint16,
  payload bytes[length],
  calc valid uint8 = start == FLAP_START and channel <= Channel.keep_alive
}
```

* The type is any integer type (`uint16`, `u7`, `int8`, ...); the value is
  any constant integer expression, may use constants declared before it, and
  must fit the type.
* The optional string after a value is a note. It becomes a doc comment in
  the generated code and is listed by `layout`.
* Expressions refer to a standalone constant by name and to a category member
  as `Category.member`. A field may not have the same name as a standalone
  constant.
* `: Category` after a field or bitfield member records where its values come
  from. Every value of the category must fit the field. `layout` shows the
  tag, and the generated struct member gets a doc comment pointing at the
  category. It does not restrict the values a field may hold.
* Category names start with an uppercase letter, since they become type names.
* Generated names change case and drop underscores, so two names that only
  differ that way (`keep_alive` and `KeepAlive`, a category and a packet) are
  rejected, as are names the generated code already uses (`Math`, `EOF`,
  `INT8_MAX`, anything starting with `pb`, ...).

### Validation

Fields can say which values are valid. Decoding fails with a `constraint`
error (naming the field) as soon as a value breaks a check, and encoding
checks before writing:

```
packet Flap be {
  start uint8 == FLAP_START,        // a magic value
  channel uint8 : Channel strict,   // one of the category's values
  ttl uint8 in 1..64,               // an inclusive range of constants
  version uint8 == 2 lenient,       // documented, but not enforced
  flags bitfield uint8 { mode u3 in 0..5, _ u5 },
  length uint16,
  payload bytes[length],
  assert length <= 1024 "payload too large"
}
```

* `== value` declares a magic value. Members with one start out holding
  it (struct defaults in Rust, Python, C#, Zig; `P_init()` in C; `NewP()` in
  Go), so building a packet only takes the fields that vary.
* `in lo..hi` and `== value` take constant expressions that must fit the
  field. Checks apply to single integer fields and bitfield members.
* `: Category strict` accepts only the values listed in the category.
* `lenient` keeps the checks in the description (`layout` and the Wireshark
  dissector show them) without enforcing them in generated codecs.
* `assert expr "message"` checks any condition over the packet's fields
  (calculated ones included) as soon as its inputs are decoded, and before
  encoding writes anything. The message is optional.

### Expressions

* literals: `42`, `0x2a`, `0b1010`, `1.5`
* named constants `FLAP_START`, `Channel.snac`
* field references `x`, array elements `x[i]`, `sumof x`, `productof x`
* arithmetic `+ - * / % ^` (power), unary `-`
* bitwise `&`, `|`, `xor`, `~`, shifts `<<` `>>`
* comparisons `== != <> < <= > >=` (not chained), `and`, `or`, `not`
* `when cond then a otherwise b`
* `sqrt(x)`, `min(a, b)`, `max(a, b)`

From loosest to tightest: `or`, `and`, `not`, comparisons, `|`, `xor`, `&`,
`<< >>`, `+ -`, `* / %`, unary `-` and `~`, `^`. So `a & 0xf == 3` compares
`a & 0xf`, and `-2 ^ 2` is `-4`.

Integer arithmetic is 64-bit two's complement with wrap-around. Integer
division truncates toward zero, `%` keeps the sign of the dividend, and
dividing by zero gives 0 for both. `>>` is an arithmetic shift; shifting by a
negative count gives 0, and by 64 or more gives 0 (`<<`) or the sign (`>>`).
An out-of-range array index gives 0. If any operand is a float the operation
is done in `float64`, and comparisons yield 1 or 0; `%`, shifts and bitwise
operators need integers. Every backend implements exactly these semantics,
and the test suite checks that they agree.

## Generated API

Every packet `P` gets a struct/class with one member per field, plus decode
from bytes, decode from a shared reader (for streams and nesting), encode,
and encode into a shared writer. Decoding ignores trailing bytes.

| language | decode | encode | errors |
|----------|--------|--------|--------|
| C | `P_decode(&p, data, len)`, `P_decode_from(&p, &reader)`; release with `P_free(&p)` | `P_encode(&p, &buf, &len)` (caller `free`s), `P_encode_to(&p, &writer)` | `PB_OK` / negative `PB_ERR_*`, `pb_strerror(rc)`; details on the reader/writer |
| Rust | `P::decode(&data)?`, `P::decode_from(&mut PbReader::new(&data))?` | `p.encode()?`, `p.encode_to(&mut writer)?` | `Result<_, PbError>` |
| Go | `DecodeP(data)`, `p.DecodeFrom(NewPbReader(data))` | `p.Encode()`, `p.EncodeTo(w)` | `error` (`*PbError`) |
| Python | `P.decode(data)`, `P.decode_from(PbReader(data))` | `p.encode()`, `p.encode_to(w)` | raises `PbError` |
| C# | `P.Decode(data)`, `P.DecodeFrom(new PbReader(data))` | `p.Encode()`, `p.EncodeTo(w)` | throws `PbException` |
| Zig | `P.decode(allocator, data)`, `P.decodeFrom(allocator, &reader)`; release with `p.deinit(allocator)` | `p.encode(allocator)`, `p.encodeTo(&writer)` | `PbError!T` |

### Errors

Every error has a **kind**, the **path** of the field it happened in
(`Snac.tlvs[3].length`) and the **bit offset** of the reader or writer:

| kind | meaning |
|------|---------|
| incomplete | the input ended before the packet did; also says how many more bits are needed at least, so a stream reader knows to wait for more data |
| invalid | malformed data: a negative length, a field that overruns its window, nesting deeper than 64 packets, ... |
| range | a value does not fit in its field (encoding) |
| text | a string is not valid text, or contains a NUL where none is allowed |
| mismatch | an array's length does not match its length expression (encoding) |
| constraint | a value breaks a declared constraint |

| language | kind | path, offset |
|----------|------|--------------|
| C | the return code: `PB_ERR_INCOMPLETE`, `PB_ERR_INVALID`, `PB_ERR_RANGE`, `PB_ERR_TEXT`, `PB_ERR_MISMATCH`, `PB_ERR_CONSTRAINT`, `PB_ERR_NOMEM` | after `P_decode_from(&p, &r)`: `r.err.bit_offset`, `r.err.needed_bits`, `pb_reader_path(&r, buf, n)`, `pb_reader_describe(&r, buf, n)` (the writer has the same) |
| Rust | `e.kind` (`PbErrorKind::Incomplete`, ...) | `e.path`, `e.bit_offset`, `e.needed_bits`; `Display` shows all three |
| Go | `err.(*PbError).Kind` (`PbIncomplete`, ...) | `.Path`, `.BitOffset`, `.NeededBits` |
| Python | `e.kind` (`PbError.INCOMPLETE`, ...) | `e.path`, `e.bit_offset`, `e.needed_bits` |
| C# | `e.Kind` (`PbErrorKind.Incomplete`, ...) | `e.Path`, `e.BitOffset`, `e.NeededBits` |
| Zig | the error (`error.Incomplete`, `error.Invalid`, `error.Range`, `error.InvalidText`, `error.Mismatch`, `error.Constraint`, `error.OutOfMemory`) | `reader.trace.diag` (`bit_offset`, `needed_bits`), `reader.trace.writePath(writer)` |

Named constants are exported with their declared type:

| language | `const FLAP_START uint8 = 0x2a` | `Channel.snac` |
|----------|--------------------------------|----------------|
| C | `FLAP_START` (`#define`) | `CHANNEL_SNAC` |
| Rust | `FLAP_START: u8` | `Channel::SNAC` |
| Go | `FlapStart uint8` | `ChannelSnac` |
| Python | `FLAP_START` | `Channel.SNAC` |
| C# | `Constants.FlapStart` | `Channel.Snac` |
| Zig | `FLAP_START: u8` | `Channel.snac` |

For C, define `PACKETS_IMPLEMENTATION` (the upper-cased `-p` name followed by
`_IMPLEMENTATION`) in exactly one `.c` file before including the header. Go and
C# member names are PascalCase (`total_length` becomes `TotalLength`). Names that are
keywords in a target language are escaped (`type` becomes `r#type` in Rust,
`type_` in C, and `@"type"` in Zig). In Zig, bit-sized fields use exact-width
types (`u3`, `i12`), so out-of-range values are compile errors. The other
languages check ranges when encoding.

## Tests

```sh
cargo test
```

* `tests/validation.rs` checks that malformed descriptions are rejected with
  the right message.
* `tests/cli.rs` covers the command line.
* `tests/codegen.rs` is the cross-language suite. For every
  `tests/specs/*.json` file it generates a parser in each language, writes a
  driver program in that language, **compiles it with the real toolchain**,
  runs every test vector through decode → JSON dump → re-encode, and compares
  the results with the expectations. Every vector is also replayed truncated
  at every length and with random bit flips. Any outcome is accepted there as
  long as the decoder fails cleanly, which, with sanitizers in C and a
  leak-checking allocator in Zig, covers the error paths. The same vectors
  also run through the reference interpreter (`ir::interp`), which needs no
  toolchain.
* `tests/examples.rs` runs the OSCAR and P3 demo programs.

Languages whose toolchain is missing are skipped with a message. Set
`PB_REQUIRE_ALL=1` to turn a missing toolchain into a failure (CI does). Zig is
looked up as `zig` on `PATH` or through `$ZIG`; C# needs a .NET SDK (`dotnet`).

A spec file looks like this:

```json
{ "spec": "features.packet",
  "cases": [
    { "name": "flags", "packet": "Flags8", "hex": "b0",
      "expect": { "one": 1, "two": 1, "three": 4 } },
    { "name": "truncated", "packet": "Flags16", "hex": "a8",
      "error_kind": "incomplete", "error_path": "Flags16.ctl" },
    { "name": "too wide", "packet": "Flags8", "hex": "b0",
      "set": { "two": 4 }, "encode_error": true },
    { "name": "padding dropped", "packet": "Flags8", "hex": "b3",
      "encoded": "b0" }
  ] }
```

`expect` lists decoded members (nested packets as objects, arrays as lists,
byte buffers as hex). `set` overwrites members (dotted paths reach into nested
packets) before re-encoding. Unless `encoded` or an error is given, re-encoding
must reproduce the input exactly. `"error": true` accepts any decode error;
`error_kind` and `error_path` (and `encode_error_kind`, `encode_error_path`)
also check what the error reports.
