"""Decode a P3 (AOL client) session and answer it.

Generate the parser first:

    cargo run -- generate examples/p3.packet -l python -p packets -o examples/out
    PYTHONPATH=examples/out python3 examples/p3_demo.py
"""

import struct

from packets import (
    P3_LENGTH_OVERHEAD, P3_SEQ_FIRST, P3_STOP, P3_SYNC, FdoProtocol, FdoStream,
    P3Init, P3Message, P3Packet, P3Type, PbError, PbReader, Platform,
)

# What a server receives from a client: the INIT packet (captured from a
# real AOL client, via the notaol project) and a "Dd" login packet.
STREAM = bytes.fromhex(
    "5ab35f00377f7fa3039d116180000000050f00001fb4b53ec00014d1032000000000040a"
    "0000014b070504ffff0000000000fffec8f718000001b2070d"
    "5a6a0a0058107fa044640016000100010a0400000001010b040000000503010a736f6d65677579202020"
    "011d00011d00010a040000000203010970617373776f726431011d00010a0400000010010b0400000001"
    "011d00011d000002000d"
)


def crc16_arc(data):
    """CRC-16/ARC (poly 0x8005 reflected, init 0), as used by P3."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def packets(stream):
    """Split a byte stream into P3 packets, checking each CRC."""
    reader = PbReader(stream)
    while reader.remaining_bits() > 0:
        start = reader.position_bits() // 8
        packet = P3Packet.decode_from(reader)
        raw = stream[start:reader.position_bits() // 8]
        if not packet.valid:
            raise PbError(PbError.CONSTRAINT, "not a P3 packet")
        if crc16_arc(raw[3:-1]) != packet.crc:
            raise PbError(PbError.MISMATCH, "CRC mismatch")
        yield packet


def control_packet(packet_type, tx_seq, rx_seq):
    """Build a control packet (ACK, NAK, ...) with a correct CRC."""
    packet = P3Packet(sync=P3_SYNC, length=P3_LENGTH_OVERHEAD, tx_seq=tx_seq, rx_seq=rx_seq,
                      always_set=1, type=packet_type, data=b"", stop=P3_STOP)
    wire = packet.encode()
    packet.crc = crc16_arc(wire[3:-1])
    return packet.encode()


def main():
    last_tx = None
    for packet in packets(STREAM):
        last_tx = packet.tx_seq
        if packet.type == P3Type.INIT:
            init = P3Init.decode(packet.data)
            platform = {Platform.WINDOWS: "Windows", Platform.MACINTOSH: "Macintosh"}.get(
                init.platform, hex(init.platform))
            # Only some INIT fields have known meanings; see docs/p3.md.
            print("INIT from a %s client, version %d.%d, session flags 0x%04x"
                  % (platform, init.client_major, init.client_minor, init.session_flags))
        elif packet.type == P3Type.DATA:
            message = P3Message.decode(packet.data)
            print("DATA token %r, %d byte(s) of FDO atoms" % (message.token, len(message.atoms)))
            if message.token == "Dd":
                # de_data atoms (display editor protocol, atom 1) hold the screen name and password.
                fields = [a.arg.decode("ascii") for a in FdoStream.decode(message.atoms).atoms
                          if a.uncompressed and (a.protocol, a.atom) == (FdoProtocol.DE, 1)]
                print("login: screen name %r, password %s" % (fields[0].rstrip(), "*" * len(fields[1])))
        else:
            print("control packet 0x%02x" % packet.type)

    reply = control_packet(P3Type.ACK, tx_seq=P3_SEQ_FIRST, rx_seq=last_tx)
    print("ACK reply:", reply.hex())
    assert next(packets(reply)).type == P3Type.ACK


if __name__ == "__main__":
    main()
