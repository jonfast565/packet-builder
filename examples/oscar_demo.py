"""Decode a captured OSCAR (AIM) TCP stream and answer an instant message.

Generate the parser first:

    cargo run -- generate examples/oscar.packet -l python -p packets -o examples/out
    PYTHONPATH=examples/out python3 examples/oscar_demo.py
"""

from packets import (
    Channel, Charset, Flap, FlapPayload, FragmentId, IcbmChannel, IcbmFragment,
    IcbmFragmentData, IcbmMessage, IcbmSend, IcbmSubtype, IcbmTlv, MessageText,
    PbReader, Snac, SnacBody, SnacFamily, Tlv,
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
                if fragment.data.kind == "text":
                    return fragment.data.value.text.decode("ascii")
    return None


def main():
    reply = None
    # Decoding a frame decodes all of it: the channel picks the payload type
    # and the SNAC family/subtype the body type. A bad start byte or channel
    # raises PbError.
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
                sender = im.screen_name
                print("message from %s (warning level %.1f%%): %s"
                      % (sender, im.warning_percent, message_text(im.tlvs)))
                reply = (frame.sequence, im.cookie, sender)

    # Answer with SNAC(04,06) inside a FLAP frame. Every length is derived
    # (`length uint16 = len(payload)`), so the encoders fill them in, and
    # FLAP's start byte defaults to FLAP_START.
    seq, cookie, sender = reply
    text = b"Hi from packet-builder!"
    fragments = IcbmMessage(fragments=[
        IcbmFragment(id=FragmentId.CAPABILITIES, version=1, data=IcbmFragmentData("other", b"\x01")),
        IcbmFragment(id=FragmentId.TEXT, version=1,
                     data=IcbmFragmentData("text", MessageText(charset=Charset.ASCII, text=text))),
    ]).encode()
    send = IcbmSend(
        cookie=cookie,
        channel=IcbmChannel.PLAIN_TEXT,
        screen_name=sender,
        tlvs=[Tlv(type=IcbmTlv.MESSAGE_DATA, value=fragments), Tlv(type=IcbmTlv.STORE_OFFLINE)],
    )
    snac = Snac(family=SnacFamily.ICBM, subtype=IcbmSubtype.SEND, request_id=0x30, body=SnacBody("send", send))
    out = Flap(channel=Channel.SNAC, sequence=(seq + 1) & 0xFFFF, payload=FlapPayload("snac", snac))
    wire = out.encode()
    print("reply frame:", wire.hex())

    # Round trip: our own frame decodes back to the same message.
    again = Flap.decode(wire).payload.value.body.value
    assert message_text(again.tlvs) == text.decode("ascii")


if __name__ == "__main__":
    main()
