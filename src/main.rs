#![macro_use]
extern crate pest;
extern crate serde;

#[macro_use]
extern crate pest_derive;

mod generators;
mod models;
mod parser;
mod utilities;

use crate::generators::c_generator::CGenerator;
use crate::generators::rust_generator::RustGenerator;
use crate::generators::zig_generator::ZigGenerator;
use crate::generators::net_generator::CSharpGenerator;

use std::fs;
use std::fs::File;
use std::path::Path;

fn main() -> std::io::Result<()> {
    println!("--- Packet Builder ---");
    let file =
        fs::read_to_string("./test_packet.packet").expect("Something went wrong reading the file");
    let packet = parser::parse_file(&file).unwrap();
    // dbg!(&packet);
    for item in vec!["c", "rust", "zig", "net"] {
        let packet_result = match item {
            "c" => CGenerator::generate(&packet),
            "rust" => RustGenerator::generate(&packet),
            "zig" => ZigGenerator::generate(&packet),
            "net" => CSharpGenerator::generate(&packet),
            _ => String::new(),
        };
        let file_extension = match item {
            "c" => "c",
            "rust" => "rs",
            "zig" => "zig",
            "net" => "cs",
            _ => "",
        };

        if !Path::new("./results").exists() {
            fs::create_dir("./results")?;
        }
        let filename = format!("./results/{}.{}", "packets", file_extension);
        File::create(&filename)?;
        fs::write(&filename, packet_result)?;
    }
    println!("{}", "Done!");
    Ok(())
}
