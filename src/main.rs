#![macro_use]
extern crate serde;
use serde_json;
use std::fs;
use combine::{many1, Parser, sep_by};
use combine::parser::sequence::{then};
use combine::parser::char::{letter, space, string, spaces, digit, char};
use combine::parser::choice::{or};
use combine::stream::easy;

mod models;
mod utilities;

fn main() {
    println!("--- Packet Builder ---");
    let serialized = fs::read_to_string("./packet_definition.json")
        .expect("Something went wrong reading the file");
    let mut deserialized: models::PacketParser = serde_json::from_str(&serialized).unwrap();
    for p in &mut deserialized.packet_groups {
        p.post_process();
    }
    dbg!(&deserialized);
    parser()
}

fn parser() {
    repeat::many()
}
