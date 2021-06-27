#![macro_use]
extern crate serde;
extern crate pest;
#[macro_use]
extern crate pest_derive;

use serde_json;
use std::fs;

mod models;
mod utilities;
mod parser;

fn main() {
    println!("--- Packet Builder ---");
    let serialized = fs::read_to_string("./packet_definition.json")
        .expect("Something went wrong reading the file");
    let mut deserialized: models::PacketParser = serde_json::from_str(&serialized).unwrap();
    for p in &mut deserialized.packet_groups {
        p.post_process();
    }
    dbg!(&deserialized);
    
}