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
use std::fs;

fn main() {
    println!("--- Packet Builder ---");
    let file =
        fs::read_to_string("./test_packet.packet").expect("Something went wrong reading the file");
    let contents = parser::parse_file(&file).unwrap();
    for packet in contents {
        let result = CGenerator::generate(&packet);
        println!("{}", result);
        let result2 = ZigGenerator::generate(&packet);
        println!("{}", result2)
    }
}
