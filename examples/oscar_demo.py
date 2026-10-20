"""Decode a captured OSCAR (AIM) TCP stream and answer an instant message.

Generate the parser first:

    cargo run -- generate examples/oscar.packet -l python -p packets -o examples/out
    PYTHONPATH=examples/out python3 examples/oscar_demo.py
"""

import struct

from packets import (
    FLAP_START, Channel, Charset, Flap, FlapSignon, FragmentId, IcbmChannel,
    IcbmMessage, IcbmReceive, IcbmSend, IcbmSubtype, IcbmTlv, MessageText,
    PbReader, ServerReady, ServiceSubtype, SnacFamily, SnacHeader, Tlv,
)

# What a client receives right after connecting to a BOS server: the sign-on
# frame, SNAC(01,03) "server ready", and an incoming message SNAC(04,07).
STREAM = bytes.fromhex(
    "2a01 1f3a 0004 00000001"
    "2a02 1f3b 0018 0001 0003 0000 00000000 0001 0002 0003 0004 0009 0013 0015"
    "2a02 1f3c 004c 0004 0007 0000 0000002f 3132333435363738 0001 09 61696d6275646479 31"
    "0019 0002 0001 0002 0010 0003 0004 3b9aca00"
    "0002 0018 0501 0001 01 0101 000f 0000 0000 48656c6c6f2c2041494d21"
    .replace(" ", "")
)


def frames(stream):
    """Split a TCP byte stream into FLAP frames."""
    reader = PbReader(stream)
    while reader.remaining_bits() > 0:
        yield Flap.decode_from(reader)


def message_text(tlvs):
    """Extract the text of a channel 1 message from its TLV chain."""
    for tlv in tlvs:
        if tlv.type == IcbmTlv.MESSAGE_DATA:
            for fragment in IcbmMessage.decode(tlv.value).fragments:
                if fragment.id == FragmentId.TEXT:
                    return MessageText.decode(fragment.data).text.decode("ascii")
    return None


def main():
    reply = None
    for frame in frames(STREAM):  # a bad start byte or channel raises PbError
        if frame.channel == Channel.SIGNON:
            print("sign-on, protocol version", FlapSignon.decode(frame.payload).version)
            continue
        header = SnacHeader.decode(frame.payload)
        kind = (header.family, header.subtype)
        if kind == (SnacFamily.SERVICE, ServiceSubtype.SERVER_READY):
            families = ServerReady.decode(frame.payload).families
            print("server ready, families:", ", ".join("0x%04x" % f for f in families))
        elif kind == (SnacFamily.ICBM, IcbmSubtype.RECEIVE):
            im = IcbmReceive.decode(frame.payload)
            sender = im.screen_name
            print("message from %s (warning level %.1f%%): %s"
                  % (sender, im.warning_percent, message_text(im.tlvs)))
            reply = (frame.sequence, im.cookie, sender)

    # Answer with SNAC(04,06) inside a FLAP frame.
    seq, cookie, sender = reply
    text = b"Hi from packet-builder!"
    fragments = (struct.pack(">BBHB", FragmentId.CAPABILITIES, 0x01, 1, 0x01)
                 + struct.pack(">BBHHH", FragmentId.TEXT, 0x01, 4 + len(text), Charset.ASCII, 0) + text)
    send = IcbmSend(
        header=SnacHeader(family=SnacFamily.ICBM, subtype=IcbmSubtype.SEND, request_id=0x30),
        cookie=cookie,
        channel=IcbmChannel.PLAIN_TEXT,
        screen_name=sender,
        tlvs=[Tlv(type=IcbmTlv.MESSAGE_DATA, length=len(fragments), value=fragments),
              Tlv(type=IcbmTlv.STORE_OFFLINE, length=0, value=b"")],
    )
    payload = send.encode()
    out = Flap(start=FLAP_START, channel=Channel.SNAC, sequence=(seq + 1) & 0xFFFF,
               length=len(payload), payload=payload)
    wire = out.encode()
    print("reply frame:", wire.hex())

    # Round trip: our own frame decodes back to the same message.
    again = IcbmSend.decode(Flap.decode(wire).payload)
    assert message_text(again.tlvs) == text.decode("ascii")


if __name__ == "__main__":
    main()
