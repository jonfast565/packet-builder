//! Decode a P3 (AOL client) session with the generated Rust parser.
//!
//!     cargo run -- examples/p3.packet -l rust -o examples/out
//!     cp examples/p3_demo.rs examples/out/ && cd examples/out
//!     rustc --edition 2021 p3_demo.rs && ./p3_demo

mod packets;

use packets::*;

const STREAM: &str = concat!(
    // INIT, captured from a real client (via the notaol project)
    "5ab35f00377f7fa3039d116180000000050f00001fb4b53ec00014d1032000000000040a",
    "0000014b070504ffff0000000000fffec8f718000001b2070d",
    // "Dd" login DATA packet
    "5a6a0a0058107fa044640016000100010a0400000001010b040000000503010a736f6d65677579202020",
    "011d00011d00010a040000000203010970617373776f726431011d00010a0400000010010b0400000001",
    "011d00011d000002000d",
);

/// CRC-16/ARC (poly 0x8005 reflected, init 0), as used by P3.
fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA001 } else { crc >> 1 };
        }
    }
    crc
}

fn main() -> Result<(), PbError> {
    let bytes: Vec<u8> =
        (0..STREAM.len() / 2).map(|i| u8::from_str_radix(&STREAM[2 * i..2 * i + 2], 16).unwrap()).collect();

    let mut reader = PbReader::new(&bytes);
    while reader.remaining_bits() > 0 {
        let start = reader.position_bits() / 8;
        let packet = P3Packet::decode_from(&mut reader)?;
        let raw = &bytes[start..reader.position_bits() / 8];
        let crc_ok = crc16_arc(&raw[3..raw.len() - 1]) == packet.crc;
        println!("type 0x{:02x} tx 0x{:02x} valid {} crc ok {}", packet.r#type, packet.tx_seq, packet.valid, crc_ok);

        match packet.r#type {
            0x23 => {
                let init = P3Init::decode(&packet.data)?;
                println!("  INIT: platform {} version {}.{}", init.platform, init.client_major, init.client_minor);
            }
            0x20 => {
                let message = P3Message::decode(&packet.data)?;
                let stream = FdoStream::decode(&message.atoms)?;
                let names: Vec<String> = stream
                    .atoms
                    .iter()
                    .filter(|a| a.uncompressed == 1 && a.protocol == 3 && a.atom == 1)
                    .map(|a| String::from_utf8_lossy(&a.arg).trim_end().to_string())
                    .collect();
                println!("  DATA {}: {} atoms, screen name {}", message.token, stream.atoms.len(), names[0]);
            }
            other => println!("  control packet 0x{:02x}", other),
        }
    }
    Ok(())
}
