#![macro_use]
extern crate pest;
extern crate serde;

#[macro_use]
extern crate pest_derive;

mod models;
mod parser;
mod utilities;
mod generators;

use crate::generators::c_generator::CGenerator;
use crate::generators::zig_generator::ZigGenerator;
use crate::generators::rust_generator::RustGenerator;

use std::fs;
use std::fs::File;

fn main() -> std::io::Result<()> {
    println!("--- Packet Builder ---");
    let file =
        fs::read_to_string("./test_packet.packet").expect("Something went wrong reading the file");
    let contents = parser::parse_file(&file).unwrap();
    for packet in contents {
        let packet_result = match "rust" {
            "c" => CGenerator::generate(&packet),
            "rust" => RustGenerator::generate(&packet),
            "zig" => ZigGenerator::generate(&packet),
            _ => String::new()
        };
        let file_extension = match "rust" {
            "c" => "c",
            "rust" => "rs",
            "zig" => "zig",
            _ => ""
        };
        println!("{}", packet_result);
        let filename = format!("{}_{}.{}", packet.name, "packet", file_extension);
        File::create(&filename)?;
        fs::write(&filename, packet_result)?;
    }
    Ok(())
}
