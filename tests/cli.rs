//! The command line interface.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packet_builder"))
}

fn out_dir(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn generate_writes_one_file_per_language() {
    let dir = out_dir("generate");
    let status =
        bin().args(["examples/network.packet", "-l", "rust,go", "-p", "net", "-o"]).arg(&dir).status().unwrap();
    assert!(status.success());
    assert!(dir.join("net.rs").is_file());
    assert!(dir.join("net.go").is_file());
    assert!(!dir.join("net.py").exists());
    assert!(std::fs::read_to_string(dir.join("net.go")).unwrap().contains("package net"));
}

#[test]
fn generate_subcommand_and_alias() {
    for cmd in ["generate", "gen"] {
        let dir = out_dir(cmd);
        let status = bin().args([cmd, "examples/oscar.packet", "-l", "python", "-o"]).arg(&dir).status().unwrap();
        assert!(status.success());
        assert!(dir.join("packets.py").is_file());
    }
}

#[test]
fn stdout_prints_code() {
    let out = bin().args(["examples/network.packet", "-l", "c", "--stdout"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("typedef struct Ipv4"));
    let out = bin().args(["examples/network.packet", "--stdout"]).output().unwrap();
    assert!(!out.status.success(), "--stdout with every language must fail");
}

#[test]
fn unknown_language_is_rejected() {
    let out = bin().args(["examples/network.packet", "-l", "cobol"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown language `cobol`"));
}

#[test]
fn check_reports_errors_with_location() {
    let dir = out_dir("check");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.packet");
    std::fs::write(&bad, "packet P { a u3, b uint16 }").unwrap();
    let out = bin().arg("check").arg("examples/oscar.packet").arg(&bad).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("examples/oscar.packet: ok"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("starts 3 bit(s) into a byte"), "{}", err);
    assert!(err.contains("bad.packet:1:18"), "{}", err);
}

#[test]
fn layout_shows_padding() {
    let out = bin().args(["layout", "tests/specs/types.packet", "-k", "CStruct"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("packet CStruct: 32 byte(s), alignment 8"), "{}", text);
    assert!(text.contains("padding to 8 byte(s)"), "{}", text);
    assert!(!text.contains("packet Dyn"), "{}", text);
}

#[test]
fn languages_lists_targets() {
    let out = bin().arg("languages").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    for l in ["c", "rust", "zig", "csharp", "python", "go"] {
        assert!(text.lines().any(|line| line.starts_with(l)), "{}", text);
    }
}
