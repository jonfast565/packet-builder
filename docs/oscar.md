# Worked example: parsing OSCAR (AIM / ICQ)

OSCAR ("Open System for CommunicAtion in Realtime") is the binary protocol
AOL Instant Messenger and ICQ used from the late 1990s onward. Its layering
makes it a good real-world test for packet-builder:

```
TCP stream ─▶ FLAP frames ─▶ SNAC (family, subtype, flags, request id) ─▶ TLV chains ─▶ values
```

[`examples/oscar.packet`](../examples/oscar.packet) describes the wire formats.
This page explains the description and then uses the generated parsers to
decode a captured session and send a reply. The same code runs in the test
suite ([`examples/oscar_demo.py`](../examples/oscar_demo.py) and
[`examples/oscar_demo.rs`](../examples/oscar_demo.rs)), and every packet below
has test vectors in [`tests/specs/oscar.json`](../tests/specs/oscar.json) that
are checked in all six languages.

## 1. FLAP: framing

Every message on an OSCAR connection is a FLAP frame: a `*` marker, a channel,
a sequence number, and a length-prefixed payload.

```
const FLAP_START uint8 = 0x2a "first byte of every FLAP frame ('*')"

const Channel uint8 {
  signon = 1        "sign-on: FlapSignon payload",
  snac = 2          "SNAC data: Snac payload",
  error = 3         "FLAP-level error",
  signoff = 4       "sign-off",
  keep_alive = 5    "keep-alive",
}

packet Flap be {
  start uint8 == FLAP_START,
  channel uint8 : Channel strict,
  sequence uint16,
  length uint16,
  payload bytes[length]
}
```

* The protocol's magic numbers are **named constants**. `Channel` is a
  category, and `channel uint8 : Channel` notes that the field takes its
  values from it. Expressions use them by name (`Channel.snac`), and every
  generated file exports them: `Channel.SNAC` in Python, `Channel::SNAC` in Rust,
  `ChannelSnac` in Go, `CHANNEL_SNAC` in C. The strings are notes that end up
  as doc comments.
* `bytes[length]` takes its size from a field decoded earlier. The decoder
  checks `length` against the remaining input before allocating, so a corrupt
  frame produces an error instead of a huge allocation or an over-read.
* `start uint8 == FLAP_START` is a **magic value**: decoding anything else
  fails with a `constraint` error (`Flap.start: ...`), encoding checks it
  too, and a new `Flap` starts out holding it. `strict` on `channel` does the
  same with the values of the `Channel` category.
* The encoder checks that `payload` really has `length` bytes.

## 2. SNAC header: a bitfield and an optional block

Channel 2 payloads start with a 10-byte SNAC header. Its 16-bit flags word
has two meaningful bits: `SnacFlag.has_version_info` (0x8000) says a
length-prefixed block of version TLVs follows the header, and
`SnacFlag.more_replies` (0x0001) says more replies to the same request will
follow.

```
const SnacFamily uint16 {
  service = 0x0001  "generic service controls",
  icbm = 0x0004     "ICBM: instant messages",
  auth = 0x0017     "authorization (MD5 login)",
}

packet SnacHeader be {
  family uint16 : SnacFamily,
  subtype uint16,           // ServiceSubtype, AuthSubtype or IcbmSubtype, by family
  flags bitfield uint16 {
    has_version_info u1,    // SnacFlag.has_version_info
    _ u14,
    more_replies u1         // SnacFlag.more_replies
  },
  request_id uint32,
  version_info SnacVersionInfo[has_version_info]
}

packet SnacVersionInfo be {
  length uint16,
  tlvs bytes[length]
}
```

* A field takes one category, so `subtype` (whose meaning depends on the
  family) is left untagged; the subtypes are still named per family
  (`ServiceSubtype.server_ready`, `IcbmSubtype.receive`, ...).
* `flags bitfield uint16 { ... }` reads one big-endian 16-bit integer and
  splits it from the most significant bit down. `_ u14` names the unused bits
  explicitly. They are ignored on decode and written as zero on encode.
* `version_info SnacVersionInfo[has_version_info]` is an **optional field**
  written as an array of 0 or 1 nested packets whose count is the flag bit.
  Set the flag without supplying the block (or the reverse) and encoding fails
  with a length mismatch, so the two can't drift apart.

## 3. TLVs and typed SNAC bodies

Most SNAC bodies are TLV chains that run to the end of the payload:

```
packet Tlv be {
  type uint16,
  length uint16,
  value bytes[length]
}

packet AuthKeyRequest be {     // SNAC(17,06)
  header SnacHeader,
  tlvs Tlv[]                   // [] = repeat until the input ends
}
```

`Tlv[]` keeps decoding `Tlv`s until the input is used up. A truncated TLV at
the end is an error rather than being silently dropped. `type` is a keyword
in several target languages; the generators escape it (`r#type` in Rust,
`type_` in C, `@"type"` in Zig, `Type` in Go and C#).

The incoming instant message, SNAC(04,07), shows how the pieces fit together:

```
packet IcbmReceive be {
  header SnacHeader,
  cookie bytes[8],
  channel uint16 : IcbmChannel,   // plain_text, rendezvous, icq
  screen_name string(uint8),      // one length byte, then the name
  warning_level uint16,           // tenths of a percent
  user_tlv_count uint16,
  user_tlvs Tlv[user_tlv_count],  // count of nested packets
  tlvs Tlv[],                     // message TLVs until the end
  calc warning_percent float64 = warning_level / 10.0
}
```

The message text sits two levels deeper: TLV `IcbmTlv.message_data` holds a
list of fragments (`IcbmMessage`), and fragment `FragmentId.text` holds a
charset header plus the text (`MessageText`). Each level is its own packet, so you decode exactly as
deep as you need.

## 4. Generating the parsers

```sh
cargo run -- generate examples/oscar.packet -o out              # every language
cargo run -- generate examples/oscar.packet -l go -o oscar      # Go package "oscar"
```

## 5. Decoding a captured session (Python)

The demo decodes what a client receives right after connecting to a BOS
server: the sign-on frame, SNAC(01,03) *server ready*, and an incoming IM.

```python
from packets import (Channel, Flap, FlapSignon, FragmentId, IcbmMessage, IcbmReceive, IcbmSubtype,
                     IcbmTlv, MessageText, PbReader, ServerReady, ServiceSubtype, SnacFamily, SnacHeader)

def frames(stream):
    """Split a TCP byte stream into FLAP frames."""
    reader = PbReader(stream)
    while reader.remaining_bits() > 0:
        yield Flap.decode_from(reader)          # decode_from shares the reader

def message_text(tlvs):
    for tlv in tlvs:
        if tlv.type == IcbmTlv.MESSAGE_DATA:
            for fragment in IcbmMessage.decode(tlv.value).fragments:
                if fragment.id == FragmentId.TEXT:
                    return MessageText.decode(fragment.data).text.decode("ascii")

for frame in frames(STREAM):
    if frame.channel == Channel.SIGNON:
        print("sign-on, protocol version", FlapSignon.decode(frame.payload).version)
        continue
    header = SnacHeader.decode(frame.payload)   # peek at family/subtype
    if (header.family, header.subtype) == (SnacFamily.SERVICE, ServiceSubtype.SERVER_READY):
        families = ServerReady.decode(frame.payload).families
        print("server ready, families:", ", ".join("0x%04x" % f for f in families))
    elif (header.family, header.subtype) == (SnacFamily.ICBM, IcbmSubtype.RECEIVE):
        im = IcbmReceive.decode(frame.payload)
        print("message from %s (warning level %.1f%%): %s"
              % (im.screen_name, im.warning_percent, message_text(im.tlvs)))
```

```
$ cargo run -- generate examples/oscar.packet -l python -p packets -o examples/out
$ PYTHONPATH=examples/out python3 examples/oscar_demo.py
sign-on, protocol version 1
server ready, families: 0x0001, 0x0002, 0x0003, 0x0004, 0x0009, 0x0013, 0x0015
message from aimbuddy1 (warning level 2.5%): Hello, AIM!
reply frame: 2a021f3d004a00040006000000000030313233343536373800010961696d62...
```

The reply is built by filling in the generated dataclasses and calling
`encode()`. It's a SNAC(04,06) inside a FLAP frame, with the sender's cookie
echoed back. Every length in OSCAR is a **derived field** (`length uint16 =
len(value)`), so the encoders compute them; decoding checks them:

```python
fragments = IcbmMessage(fragments=[
    IcbmFragment(id=FragmentId.CAPABILITIES, version=1, data=b"\x01"),
    IcbmFragment(id=FragmentId.TEXT, version=1, data=MessageText(charset=Charset.ASCII, text=text).encode()),
]).encode()
send = IcbmSend(
    header=SnacHeader(family=SnacFamily.ICBM, subtype=IcbmSubtype.SEND, request_id=0x30),
    cookie=cookie, channel=IcbmChannel.PLAIN_TEXT,
    screen_name=sender,                               # length prefix is written for you
    tlvs=[Tlv(type=IcbmTlv.MESSAGE_DATA, value=fragments), Tlv(type=IcbmTlv.STORE_OFFLINE)],
)
wire = Flap(channel=Channel.SNAC, sequence=seq + 1, payload=send.encode()).encode()
```

## 6. The same in other languages

**Rust** ([full program](../examples/oscar_demo.rs)):

```rust
let mut reader = PbReader::new(&bytes);
while reader.remaining_bits() > 0 {
    let frame = Flap::decode_from(&mut reader)?;
    if frame.channel != Channel::SNAC { continue; }
    let header = SnacHeader::decode(&frame.payload)?;
    if (header.family, header.subtype) == (SnacFamily::ICBM, IcbmSubtype::RECEIVE) {
        let im = IcbmReceive::decode(&frame.payload)?;
        println!("{} says {:?}", im.screen_name, message_text(&im.tlvs)?);
    }
}
```

**Go** (`-l go -p oscar`):

```go
flap, err := oscar.DecodeFlap(frame)
if err != nil {
    log.Fatal(err)
}
ready, err := oscar.DecodeServerReady(flap.Payload)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("SNAC(%02x,%02x) families %v\n", ready.Header.Family, ready.Header.Subtype, ready.Families)
// SNAC(01,03) families [1 2 3 4 9 19 21]

flap.Length = 3
_, err = flap.Encode()
// field `payload` has 24 element(s) but its length expression says 3
```

**C** (`-l c -p oscar`, a single header):

```c
#define OSCAR_IMPLEMENTATION
#include "oscar.h"

Flap flap;
ServerReady ready;
int rc = Flap_decode(&flap, frame, sizeof frame);
if (rc != PB_OK) { fprintf(stderr, "%s\n", pb_strerror(rc)); return 1; }
if (ServerReady_decode(&ready, flap.payload, flap.payload_len) == PB_OK) {
    printf("%zu families\n", ready.families_len);
    ServerReady_free(&ready);       /* decoders allocate arrays */
}
Flap_free(&flap);
```

C#, Zig and the other languages follow the same pattern; see the
[API table](../README.md#generated-api).

## 7. What is covered

The OSCAR description models these SNACs, each with test vectors:

| SNAC | packet |
|------|--------|
| `Channel.signon` sign-on | `FlapSignon` (version + TLVs, e.g. `LoginTlv.auth_cookie`) |
| any | `Snac` (header + raw body), `SnacHeader` |
| (01,03) server ready | `ServerReady` |
| (01,07) rate limits | `RateInfo`, `RateClass`, `RateGroup`, `FamilySubtype` |
| (01,17) / (01,18) family versions | `FamilyVersions`, `FamilyVersion` |
| (17,06) / (17,07) MD5 login key | `AuthKeyRequest`, `AuthKeyResponse` |
| (04,06) / (04,07) instant messages | `IcbmSend`, `IcbmReceive`, `IcbmMessage`, `IcbmFragment`, `MessageText` |

Adding another SNAC is usually a few lines: a header, its fixed fields, and
`tlvs Tlv[]`.
