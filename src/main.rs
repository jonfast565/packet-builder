#![macro_use]
extern crate pest;
extern crate serde;

#[macro_use]
extern crate pest_derive;

mod models;
mod parser;
mod utilities;

use std::fs;

fn main() {
    println!("--- Packet Builder ---");
    let file =
        fs::read_to_string("./test_packet.packet").expect("Something went wrong reading the file");
    let contents = parser::parse_file(&file);
    dbg!(&contents);
}
