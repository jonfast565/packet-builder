# packet-builder

A small language for describing binary packets, similar to Protocol Buffers but
aimed at *existing* wire formats: you describe the bytes (and bits) a protocol
already uses, and packet-builder generates a decoder and encoder for

| language | output | toolchain used by the tests |
|----------|--------|-----------------------------|
| C        | single-header library (`packets.h`, C99) | `cc` with ASan + UBSan |
| Rust     | one module (`packets.rs`), no dependencies | `rustc` |
| Go       | one file (`packets.go`), standard library only (Go 1.18+) | `go vet`, `gofmt`, `go build` |
| Python   | one module (`packets.py`), standard library only | `python3` |
| C#       | one file (`packets.cs`), base class library only | `dotnet` / `csc` |
| Zig      | one file (`packets.zig`, Zig 0.13) | `zig build-exe` with a leak-checking allocator |

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
cargo run -- examples/oscar.packet -o out              # generate every language
cargo run -- generate examples/oscar.packet -l rust,go # a subset (`gen` for short)
cargo run -- examples/oscar.packet -p oscar            # file stem / Go package / C# namespace
cargo run -- examples/oscar.packet -l python --stdout  # print instead of writing files
cargo run -- check examples/*.packet                   # validate only
cargo run -- layout tests/specs/types.packet -k CStruct
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

The crate is also a library: `packet_builder::generate(source, Language::Go, &GenOptions::default())`.

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

### Expressions

* literals: `42`, `0x2a`, `0b1010`, `1.5`
* field references `x`, array elements `x[i]`, `sumof x`, `productof x`
* `+ - * / ^`, comparisons `== != <> < <= > >=` (not chained), `and`, `or`
* `when cond then a otherwise b`
* `sqrt(x)`, `min(a, b)`, `max(a, b)`

Integer arithmetic is 64-bit two's complement with wrap-around. Integer
division truncates toward zero, and division by zero gives 0. An out-of-range
array index gives 0. If any operand is a float the operation is done in
`float64`, and comparisons yield 1 or 0. Every backend implements exactly
these semantics, and the test suite checks that they agree.

## Generated API

Every packet `P` gets a struct/class with one member per field, plus decode
from bytes, decode from a shared reader (for streams and nesting), encode,
and encode into a shared writer. Decoding ignores trailing bytes.

| language | decode | encode | errors |
|----------|--------|--------|--------|
| C | `P_decode(&p, data, len)`, `P_decode_from(&p, &reader)`; release with `P_free(&p)` | `P_encode(&p, &buf, &len)` (caller `free`s), `P_encode_to(&p, &writer)` | `PB_OK` / negative `PB_ERR_*`, `pb_strerror(rc)` |
| Rust | `P::decode(&data)?`, `P::decode_from(&mut PbReader::new(&data))?` | `p.encode()?`, `p.encode_to(&mut writer)?` | `Result<_, PbError>` |
| Go | `DecodeP(data)`, `p.DecodeFrom(NewPbReader(data))` | `p.Encode()`, `p.EncodeTo(w)` | `error` (`*PbError`) |
| Python | `P.decode(data)`, `P.decode_from(PbReader(data))` | `p.encode()`, `p.encode_to(w)` | raises `PbError` |
| C# | `P.Decode(data)`, `P.DecodeFrom(new PbReader(data))` | `p.Encode()`, `p.EncodeTo(w)` | throws `PbException` |
| Zig | `P.decode(allocator, data)`, `P.decodeFrom(allocator, &reader)`; release with `p.deinit(allocator)` | `p.encode(allocator)`, `p.encodeTo(&writer)` | `PbError!T` |

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
  leak-checking allocator in Zig, covers the error paths.
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
    { "name": "truncated", "packet": "Flags16", "hex": "a8", "error": true },
    { "name": "too wide", "packet": "Flags8", "hex": "b0",
      "set": { "two": 4 }, "encode_error": true },
    { "name": "padding dropped", "packet": "Flags8", "hex": "b3",
      "encoded": "b0" }
  ] }
```

`expect` lists decoded members (nested packets as objects, arrays as lists,
byte buffers as hex). `set` overwrites members (dotted paths reach into nested
packets) before re-encoding. Unless `encoded` or an error is given, re-encoding
must reproduce the input exactly.
