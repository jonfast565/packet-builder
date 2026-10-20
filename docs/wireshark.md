# Wireshark dissectors

`packet_builder dissector` turns a packet description into a Wireshark Lua
dissector (Wireshark 4.4 or later). The dissector decodes exactly like the
generated codecs, shows every field in the packet tree with a display filter
name, and reports problems as expert info instead of giving up.

## Declaring a dissector

Add a `dissector` declaration for the packet that starts each message:

```
dissector Flap { name "AIM OSCAR", abbrev "oscar", tcp.port 5190 }
```

| option | meaning |
|--------|---------|
| `name "..."` | the protocol's name, shown in the packet tree and the Protocol column (default: the packet's name) |
| `abbrev "..."` | the filter name and field prefix: lowercase letters, digits, `_`, `-`, `.` (default: the packet's name in lowercase) |
| `tcp.port 5190`, `udp.port 53`, `ethertype 0x88b5`, `ip.proto 253`, ... | register in that dissector table, for that value |
| `heuristic` | also try the dissector on TCP and UDP payloads (those of its tables, or both); it is kept only if every field check, `strict` category, assertion and derived field holds |

A file may declare several dissectors; one Lua file registers all of them.
Packets with parameters cannot have a dissector of their own.

The options can also be given on the command line, which overrides the file
(or declares a dissector the file does not have):

```sh
packet_builder dissector examples/oscar.packet -o out            # writes out/oscar.lua
packet_builder dissector proto.packet -k Frame --abbrev myproto --table udp.port=4000 --heuristic -o out
```

Load the result with `wireshark -X lua_script:out/oscar.lua` (or `tshark`), or
copy it into Wireshark's personal Lua plugins folder (Help > About Wireshark >
Folders).

## What it shows

Each member becomes a field named `<abbrev>.<packet>.<member>` in lowercase
(`oscar.flap.channel`), so it works in display filters
(`oscar.icbmreceive.screen_name == "aimbuddy1"`), columns and `tshark -e`.

| construct | in the tree |
|-----------|-------------|
| integer | an integer field (decimal; hex for `== value` fields), highlighting its bits |
| `: Category` | the value with the constant's name: `channel: snac (2)` |
| bitfield member | a field over its container's bytes |
| string, bytes | string and byte fields; strings are decoded from their text encoding |
| nested packet | a subtree `name: Packet` |
| array | a subtree with one item per element |
| union | the chosen arm, labelled `member (arm)` |
| calculated field | a generated field, in brackets |
| `at` field | a subtree for the packet at its offset |

Union arms holding integers or bytes are fields too: `<abbrev>.<union>.<arm>`
(`oscar.flappayload.other` for FLAP's `_ => other bytes[]`).

## Problems

* A field check (`== value`, `in a..b`, `strict`), an assertion or a derived
  field (lengths, checksums) that does not hold is a warning; dissection goes
  on. A wrong P3 CRC:

  ```
  AOL P3
      sync: 0x5a
      crc: 27149
      length: 3
      ...
      [Expert Info (Warning/Checksum): crc: 0x6a0d [incorrect, should be 0x6a0c]]
  ```

* Data that cannot be decoded (cut off, a bad length, an unknown union arm,
  invalid text) stops dissection with a "Malformed packet" error that names
  the field. A FLAP cut short: `Flap.payload: the window needs 608 more bit(s), 176 left`.
  Everything decoded before it stays in the tree.

## TCP

Messages follow each other in a TCP stream and need not line up with
segments. When the packet's length follows from fixed-offset header fields
(FLAP: 6 bytes, then `length` more), the dissector uses Wireshark's
`dissect_tcp_pdus`, which reassembles messages split across segments.
Otherwise it decodes messages back to back and asks TCP for more data when
one is cut off.

The OSCAR session from [oscar.md](oscar.md), in two segments that split the
second FLAP:

```
$ tshark -X lua_script:out/oscar.lua -r session.pcap -T fields -e oscar.flap.channel -e oscar.icbmreceive.screen_name
1
2,2	aimbuddy1
```

and one frame in full:

```
AIM OSCAR
    start: 0x2a
    channel: snac (2)
    sequence: 7996
    length: 76
    payload (snac): Snac
        family: icbm (4)
        subtype: 7
        ...
        body (receive): IcbmReceive
            cookie: 3132333435363738
            channel: plain_text (1)
            screen_name: aimbuddy1
            warning_level: 25
            [warning_percent: 2.5]
            user_tlv_count: 2
            user_tlvs
                [0]: Tlv
                    type: 1
                    length: 2
                    value: 0010
                ...
```

## Other scripts

The generated file returns (and sets the global `packet_builder_<package>`)
a table for other Lua scripts: `dissect(packet, fields, experts, tvb, tree)`
dissects any packet of the description, and `register(abbrev, name, packet)`
creates a protocol and returns it with its fields and experts. Load it with
`dofile`, since Wireshark gives each plugin its own globals.

## Testing

`tests/wireshark.rs` runs every spec vector through tshark: each value the
spec expects must appear as a field value, failing vectors must produce
expert info, and no vector (truncated and bit-flipped variants included) may
cause a Lua error. It also checks TCP reassembly and heuristic dissection.
The test is skipped without tshark, unless `PB_REQUIRE_ALL` is set; CI
installs tshark from the Wireshark PPA.
