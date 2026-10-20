//! `Module::frame_length`: a packet's size from its header.

use packet_builder::compile_file;
use packet_builder::ir::interp;
use std::path::Path;

/// The frame length `packet` gives for `bytes`, evaluated with the interpreter.
fn length(file: &str, packet: &str, hex: &str) -> Option<(u64, i64)> {
    let m = compile_file(Path::new(file)).unwrap_or_else(|e| panic!("{}", e.render()));
    let p = m.packets.iter().find(|p| p.name == packet).unwrap();
    let f = m.frame_length(p)?;
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    Some((f.header_bytes, interp::frame_length(&m, p, &f, &bytes).unwrap()))
}

#[test]
fn header_lengths() {
    // FLAP: 6 header bytes, then `length` bytes.
    assert_eq!(length("examples/oscar.packet", "Flap", "2a02000100040000"), Some((6, 10)));
    // UDP: `length` counts the whole datagram.
    assert_eq!(length("examples/network.packet", "Udp", "0001000200090000"), Some((8, 9)));
    // IPv4: the payload window follows options, so its offset is not fixed.
    assert_eq!(length("examples/network.packet", "Ipv4", ""), None);
    // Fixed-size packets need no header.
    assert_eq!(length("tests/specs/types.packet", "CStruct", &"00".repeat(32)), Some((32, 32)));
}
