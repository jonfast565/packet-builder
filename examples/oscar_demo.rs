//! Decode a captured OSCAR (AIM) TCP stream with the generated Rust parser.
//!
//!     cargo run -- generate examples/oscar.packet -l rust -p packets -o examples/out
//!     cp examples/oscar_demo.rs examples/out/ && cd examples/out
//!     rustc --edition 2024 oscar_demo.rs && ./oscar_demo

mod packets;

use packets::*;

const STREAM: &str = concat!(
    "2a011f3a000400000001",
    "2a021f3b0018000100030000000000000001000200030004000900130015",
    "2a021f3c004c000400070000",
    "0000002f313233343536373800010961696d6275646479310019000200010002",
    "0010000300043b9aca00000200180501000101010100",
    "0f0000000048656c6c6f2c2041494d21",
);

fn message_text(tlvs: &[Tlv]) -> Result<Option<String>, PbError> {
    for tlv in tlvs.iter().filter(|t| t.r#type == IcbmTlv::MESSAGE_DATA) {
        for fragment in IcbmMessage::decode(&tlv.value)?.fragments {
            if let IcbmFragmentData::Text(text) = fragment.data {
                return Ok(Some(String::from_utf8_lossy(&text.text).into_owned()));
            }
        }
    }
    Ok(None)
}

fn main() -> Result<(), PbError> {
    let bytes: Vec<u8> = (0..STREAM.len() / 2)
        .map(|i| u8::from_str_radix(&STREAM[2 * i..2 * i + 2], 16).unwrap())
        .collect();

    // FLAP frames follow each other on the TCP stream. Decoding a frame
    // decodes all of it: the channel picks the payload, and the SNAC family
    // and subtype pick the body.
    let mut reader = PbReader::new(&bytes);
    while reader.remaining_bits() > 0 {
        let frame = Flap::decode_from(&mut reader)?;
        let FlapPayload::Snac(snac) = &frame.payload else {
            println!("channel {} frame, {} byte(s)", frame.channel, frame.length);
            continue;
        };
        match &snac.body {
            SnacBody::ServerReady(ready) => println!("server ready: {:x?}", ready.families),
            SnacBody::Receive(im) => println!(
                "message from {} ({}% warning): {}",
                im.screen_name,
                im.warning_percent,
                message_text(&im.tlvs)?.unwrap_or_default()
            ),
            _ => println!("SNAC {:04x}/{:04x}", snac.family, snac.subtype),
        }
    }
    Ok(())
}
