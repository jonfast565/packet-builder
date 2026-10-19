//! The demo programs in examples/ run against freshly generated parsers.

#[allow(dead_code)]
mod harness;

use std::fs;
use std::process::Command;

use packet_builder::{GenOptions, Language, generate};

fn generated(lang: Language, dir: &std::path::Path) {
    let src = fs::read_to_string("examples/oscar.packet").unwrap();
    let code = generate(&src, lang, &GenOptions::default()).unwrap();
    fs::write(dir.join(format!("packets.{}", lang.extension())), code).unwrap();
}

#[test]
fn python_oscar_demo() {
    if harness::which("python3").is_none() {
        eprintln!("skipping: python3 not found");
        return;
    }
    let dir = harness::work_dir(Language::Python, "oscar_demo");
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
    let dir = harness::work_dir(Language::Rust, "oscar_demo");
    generated(Language::Rust, &dir);
    fs::copy("examples/oscar_demo.rs", dir.join("oscar_demo.rs")).unwrap();
    harness::run(
        Command::new("rustc").current_dir(&dir).args([
            "--edition",
            "2021",
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
