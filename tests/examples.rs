//! The demo programs in examples/ run against freshly generated parsers.

#[allow(dead_code)]
mod harness;

use std::fs;
use std::process::Command;

use packet_builder::{GenOptions, Language, generate};

fn generated(lang: Language, dir: &std::path::Path) {
    generated_from("examples/oscar.packet", lang, dir);
}

fn generated_from(spec: &str, lang: Language, dir: &std::path::Path) {
    let src = fs::read_to_string(spec).unwrap();
    let code = generate(&src, lang, &GenOptions::default()).unwrap();
    fs::write(dir.join(format!("packets.{}", lang.extension())), code).unwrap();
}

#[test]
fn python_oscar_demo() {
    if harness::which("python3").is_none() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = harness::work_dir("python", "oscar_demo");
    generated(Language::Python, &dir);
    let out = harness::run(
        Command::new("python3").arg(fs::canonicalize("examples/oscar_demo.py").unwrap()).env("PYTHONPATH", &dir),
        "oscar_demo.py",
    )
    .unwrap();
    assert!(out.contains("message from aimbuddy1 (warning level 2.5%): Hello, AIM!"), "{}", out);
    assert!(out.contains("reply frame: 2a021f3d"), "{}", out);
}

#[test]
fn rust_oscar_demo() {
    if harness::which("rustc").is_none() {
        eprintln!("skipping: rustc not found");
        return;
    }
    let dir = harness::work_dir("rust", "oscar_demo");
    generated(Language::Rust, &dir);
    fs::copy("examples/oscar_demo.rs", dir.join("oscar_demo.rs")).unwrap();
    harness::run(
        Command::new("rustc").current_dir(&dir).args([
            "--edition",
            "2024",
            "-D",
            "warnings",
            "oscar_demo.rs",
            "-o",
            "demo",
        ]),
        "rustc",
    )
    .unwrap();
    let out = harness::run(&mut Command::new(dir.join("demo")), "oscar demo").unwrap();
    assert!(out.contains("message from aimbuddy1 (2.5% warning): Hello, AIM!"), "{}", out);
    assert!(out.contains("server ready: [1, 2, 3, 4, 9, 13, 15]"), "{}", out);
}

#[test]
fn python_p3_demo() {
    if harness::which("python3").is_none() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = harness::work_dir("python", "p3_demo");
    generated_from("examples/p3.packet", Language::Python, &dir);
    let out = harness::run(
        Command::new("python3").arg(fs::canonicalize("examples/p3_demo.py").unwrap()).env("PYTHONPATH", &dir),
        "p3_demo.py",
    )
    .unwrap();
    assert!(out.contains("INIT from a Windows client, version 157.17, session flags 0x14d1"), "{}", out);
    assert!(out.contains("login: screen name 'someguy', password *********"), "{}", out);
    assert!(out.contains("ACK reply: 5a5a0c00031010240d"), "{}", out);
}

#[test]
fn rust_p3_demo() {
    if harness::which("rustc").is_none() {
        eprintln!("skipping: rustc not found");
        return;
    }
    let dir = harness::work_dir("rust", "p3_demo");
    generated_from("examples/p3.packet", Language::Rust, &dir);
    fs::copy("examples/p3_demo.rs", dir.join("p3_demo.rs")).unwrap();
    harness::run(
        Command::new("rustc").current_dir(&dir).args([
            "--edition",
            "2024",
            "-D",
            "warnings",
            "p3_demo.rs",
            "-o",
            "demo",
        ]),
        "rustc",
    )
    .unwrap();
    let out = harness::run(&mut Command::new(dir.join("demo")), "p3 demo").unwrap();
    assert!(out.contains("type 0x23 tx 0x7f crc 0xb35f"), "{}", out);
    assert!(out.contains("type 0x20 tx 0x10 crc 0x6a0a"), "{}", out);
    assert!(out.contains("DATA Dd: 14 atoms, screen name someguy"), "{}", out);
}
