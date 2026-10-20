//! The `doc`, `diff` and `fuzz` tools.

#[allow(dead_code)]
mod harness;

use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::tools::{diff, doc, fuzz};
use packet_builder::{compile, compile_file};

#[test]
fn doc_draws_bit_diagrams() {
    let m = compile_file(Path::new("examples/oscar.packet")).unwrap();
    let text = doc::document(&m, "OSCAR");
    assert!(text.starts_with("# OSCAR\n"), "{}", text);
    assert!(text.contains("|     start     |    channel    |           sequence            |"), "{}", text);
    assert!(text.contains("/                          payload ...                          /"), "{}", text);
    assert!(text.contains("| 1 | 1 | `channel` | u8 : Channel strict |"), "{}", text);
    assert!(text.contains("### Channel (u8)"), "{}", text);

    // Sub-byte fields share a line.
    let m = compile("packet Bits be { a u4, b u4, c u16, d u8 }").unwrap();
    let d = doc::diagram(&m.layout(&m.packets[0]));
    assert!(d.contains("|   a   |   b   |               c               |       d       |"), "{}", d);
}

fn changes(old: &str, new: &str) -> Vec<(bool, String)> {
    let (a, b) = (compile(old).unwrap(), compile(new).unwrap());
    diff::diff(&a, &b).into_iter().map(|c| (c.compatible, c.message)).collect()
}

#[test]
fn diff_finds_wire_changes() {
    let base = "const Kind uint8 { a = 1, b = 2 }\npacket P be { k uint8 : Kind, n uint16, body switch k { 1 => x uint8, _ => rest bytes[] } }";
    assert!(changes(base, base).is_empty());
    let c = changes(base, &base.replace("n uint16", "n uint32"));
    assert!(
        c.contains(&(false, "P: field `n` changed from 2 bytes big-endian to 4 bytes big-endian".into())),
        "{:?}",
        c
    );
    let c = changes(base, &base.replace("P be", "P le"));
    assert!(c.iter().any(|(ok, m)| !ok && m.contains("little-endian")), "{:?}", c);
    let c = changes(base, &base.replace("k uint8 : Kind, n uint16", "n uint16, k uint8 : Kind"));
    assert!(c.iter().any(|(ok, m)| !ok && m.contains("moved")), "{:?}", c);
    let c = changes(base, &base.replace(", n uint16", ""));
    assert!(c.contains(&(false, "P: field `n` was removed".into())), "{:?}", c);
    let c = changes(base, &base.replace("b = 2", "b = 2, c = 3"));
    assert_eq!(c, [(true, "new Kind.c = 3".to_string())]);
    let c = changes(base, &base.replace("b = 2", "b = 4"));
    assert_eq!(c, [(false, "Kind.b changed from 2 to 4".to_string())]);
    let c = changes(base, &base.replace("1 => x uint8,", "1 => x uint8, 2 => y uint16,"));
    assert_eq!(c, [(true, "PBody: new arm `y` for [2]".to_string())]);
    let c = changes(base, &format!("{}\npacket Q {{ z uint8 }}", base));
    assert_eq!(c, [(true, "new packet `Q`".to_string())]);
}

#[test]
fn diff_command_fails_on_incompatible_changes() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("diff");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a.packet"), "packet P { n uint16 }").unwrap();
    fs::write(dir.join("b.packet"), "packet P { n uint32 }").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_packet_builder"))
        .args(["diff", dir.join("a.packet").to_str().unwrap(), dir.join("b.packet").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("incompatible: P: field `n` changed"));
}

/// Every vector of every spec (with the truncated and bit-flipped variants):
/// (spec name, packet, bytes).
fn vectors() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for spec in harness::load_specs() {
        for c in &spec.cases {
            out.push((spec.name.clone(), c.packet.clone(), c.hex.clone()));
        }
    }
    out
}

#[test]
fn rust_fuzz_round_trips_hold_for_every_vector() {
    if harness::which("rustc").is_none() {
        return;
    }
    let all = vectors();
    for spec in harness::load_specs() {
        let dir = harness::work_dir("fuzz-rust", &spec.name);
        let files = fuzz::rust_project(&spec.module, "spec");
        for (name, text) in &files {
            let path = dir.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        assert!(
            files.iter().any(|(n, _)| n == "Cargo.toml") && files.iter().any(|(n, _)| n.starts_with("fuzz_targets/"))
        );
        let mut main = String::from(
            "#[path = \"src/packets.rs\"]\nmod packets;\n#[path = \"src/roundtrip.rs\"]\nmod roundtrip;\n\n",
        );
        main.push_str("fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }\n\nfn main() {\n");
        for (_, packet, hex) in all.iter().filter(|v| v.0 == spec.name) {
            if spec.module.packets.iter().any(|p| &p.name == packet && p.params.is_empty()) {
                main.push_str(&format!("    roundtrip::roundtrip_{}(&unhex(\"{}\"));\n", packet, hex));
            }
        }
        main.push_str("}\n");
        fs::write(dir.join("main.rs"), main).unwrap();
        harness::run(
            Command::new("rustc").current_dir(&dir).args([
                "--edition",
                "2024",
                "-A",
                "warnings",
                "main.rs",
                "-o",
                "run",
            ]),
            "rustc",
        )
        .unwrap_or_else(|e| panic!("{}: {}", spec.name, e));
        harness::run(&mut Command::new(dir.join("run")), "round trips")
            .unwrap_or_else(|e| panic!("{}: {}", spec.name, e));
    }
}

#[test]
fn c_fuzz_harnesses_build_and_hold_for_every_vector() {
    let Some(cc) = ["cc", "clang", "gcc"].into_iter().find(|c| harness::which(c).is_some()) else { return };
    let spec = harness::load_specs().into_iter().find(|s| s.name == "oscar").unwrap();
    let dir = harness::work_dir("fuzz-c", "oscar");
    for (name, text) in fuzz::c_harnesses(&spec.module, "oscar") {
        fs::write(dir.join(name), text).unwrap();
    }
    let mut inputs = Vec::new();
    for (i, (_, packet, hex)) in vectors().iter().filter(|v| v.0 == "oscar" && v.1 == "Flap").enumerate() {
        let bytes: Vec<u8> =
            (0..hex.len()).step_by(2).map(|j| u8::from_str_radix(&hex[j..j + 2], 16).unwrap()).collect();
        let path = dir.join(format!("in{}-{}", i, packet));
        fs::write(&path, bytes).unwrap();
        inputs.push(path);
    }
    harness::run(
        Command::new(cc).current_dir(&dir).args([
            "-g",
            "-std=c11",
            "-Wall",
            "-Werror",
            "-DPB_FUZZ_MAIN",
            "-fsanitize=address,undefined",
            "fuzz_flap.c",
            "-o",
            "run_flap",
            "-lm",
        ]),
        "cc",
    )
    .unwrap();
    harness::run(Command::new(dir.join("run_flap")).args(&inputs), "fuzz harness").unwrap();
}
