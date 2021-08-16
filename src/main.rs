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

fn main() {
    println!("--- Packet Builder ---");
    let result_type = "rust";
    let file =
        fs::read_to_string("./test_packet.packet").expect("Something went wrong reading the file");
    let contents = parser::parse_file(&file).unwrap();
    for packet in contents {
        let packet_result = match result_type {
            "c" => CGenerator::generate(&packet),
            "rust" => RustGenerator::generate(&packet),
            "zig" => ZigGenerator::generate(&packet),
            _ => String::new()
        };
        println!("{}", packet_result);
    }
}
