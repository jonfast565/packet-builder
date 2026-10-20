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
a sequence number, and a length-prefixed payload whose type depends on the
channel.

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
  length uint16 = sizeof(payload),
  payload switch channel {
    Channel.signon => signon FlapSignon,
    Channel.snac => snac Snac,
    _ => other bytes[]      // error, sign-off and keep-alive frames
  } size length
}
```

* The protocol's magic numbers are **named constants**. `Channel` is a
  category, and `channel uint8 : Channel` notes that the field takes its
  values from it. Expressions use them by name (`Channel.snac`), and every
  generated file exports them: `Channel.SNAC` in Python, `Channel::SNAC` in Rust,
  `ChannelSnac` in Go, `CHANNEL_SNAC` in C. The strings are notes that end up
  as doc comments.
* `payload switch channel { ... }` is a **tagged union**: the channel picks
  which packet the payload is decoded as, and `_` catches every other
  channel as raw bytes. Generated code gets a union type (`FlapPayload`: an
  enum in Rust, a `kind` + value in Python, a tagged struct in C) and
  encoders check that the channel matches the arm the payload holds.
* `size length` gives the payload a **window** of exactly `length` bytes:
  decoding cannot read past it, and anything the arm leaves unread is
  skipped, so a newer peer that appends fields does not break older
  decoders. `length uint16 = sizeof(payload)` is a **derived field**:
  encoders compute it, and decoders check it.
* `start uint8 == FLAP_START` is a **magic value**: decoding anything else
  fails with a `constraint` error (`Flap.start: ...`), encoding checks it
  too, and a new `Flap` starts out holding it. `strict` on `channel` does the
  same with the values of the `Channel` category.

## 2. SNAC: a header and a body picked by family and subtype

Channel 2 payloads are SNACs: a 10-byte header, then a body whose type
depends on the family and subtype. The header's 16-bit flags word has two
meaningful bits: `SnacFlag.has_version_info` (0x8000) says a length-prefixed
block of version TLVs follows the header, and `SnacFlag.more_replies`
(0x0001) says more replies to the same request will follow.

```
const SnacFamily uint16 {
  service = 0x0001  "generic service controls",
  icbm = 0x0004     "ICBM: instant messages",
  auth = 0x0017     "authorization (MD5 login)",
}

packet Snac be {
  family uint16 : SnacFamily,
  subtype uint16,           // ServiceSubtype, AuthSubtype or IcbmSubtype, by family
  flags bitfield uint16 {
    has_version_info u1,    // SnacFlag.has_version_info
    _ u14,
    more_replies u1         // SnacFlag.more_replies
  },
  request_id uint32,
  version_info SnacVersionInfo[has_version_info],
  body switch family << 16 | subtype {
    SnacFamily.service << 16 | ServiceSubtype.server_ready => server_ready ServerReady,
    SnacFamily.service << 16 | ServiceSubtype.rate_info => rate_info RateInfo,
    ...
    SnacFamily.icbm << 16 | IcbmSubtype.receive => receive IcbmReceive,
    _ => other bytes[]
  }
}

packet SnacVersionInfo be {
  length uint16 = len(tlvs),
  tlvs bytes[length]
}
```

* A field takes one category, so `subtype` (whose meaning depends on the
  family) is left untagged; the subtypes are still named per family
  (`ServiceSubtype.server_ready`, `IcbmSubtype.receive`, ...).
* The union's selector is an expression, `family << 16 | subtype`, and each
  arm lists constant values of it. Two values may pick the same arm (family
  versions are `0x0017` from the client and `0x0018` from the server).
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
  length uint16 = len(value),
  value bytes[length]
}

packet AuthKeyRequest be {     // SNAC(17,06)
  tlvs Tlv[]                   // [] = repeat until the input ends
}
```

`Tlv[]` keeps decoding `Tlv`s until the input is used up: here, until the end
of the FLAP payload's window. A truncated TLV at the end is an error rather
than being silently dropped. `type` is a keyword in several target languages;
the generators escape it (`r#type` in Rust, `type_` in C, `@"type"` in Zig,
`Type` in Go and C#).

The incoming instant message, SNAC(04,07), shows how the pieces fit together:

```
packet IcbmReceive be {
  cookie bytes[8],
  channel uint16 : IcbmChannel,   // plain_text, rendezvous, icq
  screen_name string(uint8),      // one length byte, then the name
  warning_level uint16,           // tenths of a percent
  user_tlv_count uint16 = len(user_tlvs),
  user_tlvs Tlv[user_tlv_count],  // count of nested packets
  tlvs Tlv[],                     // message TLVs until the end
  calc warning_percent float64 = warning_level / 10.0
}
```

The message text sits deeper: TLV `IcbmTlv.message_data` holds a list of
fragments (`IcbmMessage`), and a fragment is another union, whose
`FragmentId.text` arm holds a charset header plus the text (`MessageText`).
TLV values stay raw bytes, since what a TLV type means depends on where it
appears; decode them as deep as you need.

## 4. Generating the parsers

```sh
cargo run -- generate examples/oscar.packet -o out              # every language
cargo run -- generate examples/oscar.packet -l go -o oscar      # Go package "oscar"
```

## 5. Decoding a captured session (Python)

The demo decodes what a client receives right after connecting to a BOS
server: the sign-on frame, SNAC(01,03) *server ready*, and an incoming IM.
Decoding a frame decodes all of it; the unions say which arm each level
took.

```python
from packets import Flap, IcbmMessage, IcbmTlv, PbReader

def frames(stream):
    """Split a TCP byte stream into FLAP frames."""
    reader = PbReader(stream)
    while reader.remaining_bits() > 0:
        yield Flap.decode_from(reader)          # decode_from shares the reader

def message_text(tlvs):
    for tlv in tlvs:
        if tlv.type == IcbmTlv.MESSAGE_DATA:
            for fragment in IcbmMessage.decode(tlv.value).fragments:
                if fragment.data.kind == "text":
                    return fragment.data.value.text.decode("ascii")

for frame in frames(STREAM):
    payload = frame.payload
    if payload.kind == "signon":
        print("sign-on, protocol version", payload.value.version)
    elif payload.kind == "snac":
        body = payload.value.body
        if body.kind == "server_ready":
            print("server ready, families:", ", ".join("0x%04x" % f for f in body.value.families))
        elif body.kind == "receive":
            im = body.value
            print("message from %s (warning level %.1f%%): %s"
                  % (im.screen_name, im.warning_percent, message_text(im.tlvs)))
```

The `decode` command shows the same tree without writing any code:
`cargo run -- decode examples/oscar.packet -k Flap --all --hex "2a01..."`.

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
echoed back. Every length in OSCAR is derived, so the encoders compute
them, and `start` defaults to `FLAP_START`. A union value names its arm
(`SnacBody("send", ...)`), and encoding checks that the selector agrees:

```python
fragments = IcbmMessage(fragments=[
    IcbmFragment(id=FragmentId.CAPABILITIES, version=1, data=IcbmFragmentData("other", b"\x01")),
    IcbmFragment(id=FragmentId.TEXT, version=1,
                 data=IcbmFragmentData("text", MessageText(charset=Charset.ASCII, text=text))),
]).encode()
send = IcbmSend(
    cookie=cookie, channel=IcbmChannel.PLAIN_TEXT,
    screen_name=sender,                               # length prefix is written for you
    tlvs=[Tlv(type=IcbmTlv.MESSAGE_DATA, value=fragments), Tlv(type=IcbmTlv.STORE_OFFLINE)],
)
snac = Snac(family=SnacFamily.ICBM, subtype=IcbmSubtype.SEND, request_id=0x30, body=SnacBody("send", send))
wire = Flap(channel=Channel.SNAC, sequence=seq + 1, payload=FlapPayload("snac", snac)).encode()
```

## 6. The same in other languages

**Rust** ([full program](../examples/oscar_demo.rs)):

```rust
let mut reader = PbReader::new(&bytes);
while reader.remaining_bits() > 0 {
    let frame = Flap::decode_from(&mut reader)?;
    if let FlapPayload::Snac(snac) = &frame.payload
        && let SnacBody::Receive(im) = &snac.body
    {
        println!("{} says {:?}", im.screen_name, message_text(&im.tlvs)?);
    }
}
```

**Go** (`-l go -p oscar`):

```go
flap, err := oscar.DecodeFlap(frame)
if err != nil {
    log.Fatal(err) // e.g. "Flap.payload.subtype: unexpected end of data: ... (at bit 64)"
}
if flap.Payload.Kind == oscar.FlapPayloadSnac && flap.Payload.Snac.Body.Kind == oscar.SnacBodyServerReady {
    snac := flap.Payload.Snac
    fmt.Printf("SNAC(%02x,%02x) families %v\n", snac.Family, snac.Subtype, snac.Body.ServerReady.Families)
}
// SNAC(01,03) families [1 2 3 4 9 19 21]

flap.Channel = oscar.ChannelSignon
_, err = flap.Encode()
// Flap.payload: `payload` holds arm `snac`, but its selector picks another arm (at bit 48)
```

**C** (`-l c -p oscar`, a single header):

```c
#define OSCAR_IMPLEMENTATION
#include "oscar.h"

Flap flap;
pb_reader r;
char why[256];
pb_reader_init(&r, frame, sizeof frame);
if (Flap_decode_from(&flap, &r) != PB_OK) {
    fprintf(stderr, "%s\n", pb_reader_describe(&r, why, sizeof why));   /* path, error, bit */
    return 1;
}
if (flap.payload.kind == FLAPPAYLOAD_SNAC && flap.payload.u.snac.body.kind == SNACBODY_SERVER_READY)
    printf("%zu families\n", flap.payload.u.snac.body.u.server_ready.families_len);
Flap_free(&flap);                    /* frees everything the decoder allocated */
```

C#, Zig and the other languages follow the same pattern; see the
[API table](../README.md#generated-api).

## 7. What is covered

The OSCAR description models these SNACs, each with test vectors:

| SNAC | packet |
|------|--------|
| `Channel.signon` sign-on | `FlapSignon` (version + TLVs, e.g. `LoginTlv.auth_cookie`) |
| any | `Snac` (header, then a body picked by family and subtype; others stay raw) |
| (01,02) client online | `ClientOnline`, `ClientFamily` |
| (01,03) server ready | `ServerReady` |
| (01,06) rate request | an empty arm |
| (01,07) rate limits | `RateInfo`, `RateClass`, `RateClassV2`, `RateGroup`, `FamilySubtype`; v1 (AIM 1.x) and v2 class layouts, told apart with `remaining` |
| (01,08) rate ack | `RateAck` |
| (01,13) message of the day | `Motd` (`MotdType`, `MotdTlv`) |
| (01,17) / (01,18) family versions | `FamilyVersions`, `FamilyVersion` |
| (17,02) / (17,03) MD5 login | `LoginRequest`, `LoginResponse` (TLVs, `LoginTlv`) |
| (17,06) / (17,07) MD5 login key | `AuthKeyRequest`, `AuthKeyResponse` |
| (04,01) ICBM error | `SnacError` (`SnacErrorCode`) |
| (04,06) / (04,07) instant messages | `IcbmSend`, `IcbmReceive`, `IcbmMessage`, `IcbmFragment`, `MessageText` |
| (04,0C) host ack | `IcbmHostAck` |
| (0B,02) stats report interval | `StatsReportInterval` (`StatsSubtype`) |

Adding another SNAC is usually a few lines: a packet with its fixed fields
and `tlvs Tlv[]`, and an arm in `Snac.body`.
