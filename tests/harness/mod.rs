//! Cross-language test driver.
//!
//! For every `tests/specs/*.json` file the driver generates a parser from
//! the referenced `.packet` file, writes a small program in the target
//! language that decodes each test vector, prints the decoded value as JSON,
//! re-encodes it and prints the bytes. The output is compared against the
//! expectations in the spec file.
//!
//! Spec file format:
//! ```json
//! { "spec": "features.packet",
//!   "cases": [
//!     { "name": "flags", "packet": "Flags8", "hex": "b0",
//!       "expect": { "one": 1, "two": 2 } },            // decoded members (subset)
//!     { "name": "short", "packet": "Item", "hex": "00", "error": true },
//!     { "name": "range", "packet": "Flags8", "hex": "b0",
//!       "set": { "two": 4 }, "encode_error": true },   // mutate, then encode
//!     { "name": "trail", "packet": "Item", "hex": "000100ff",
//!       "encoded": "00010000" }                         // expected re-encoding
//!   ] }
//! ```
//! Unless `encoded` or an error is given, re-encoding must reproduce `hex`.

pub mod c;
pub mod csharp;
pub mod go;
pub mod python;
pub mod rust;
pub mod zig;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::ir::{Member, Module, Packet};
use packet_builder::{GenOptions, Language};
use serde_json::Value;

pub struct Case {
    pub name: String,
    pub packet: String,
    pub hex: String,
    /// Scalar members to overwrite before encoding: (member name, value).
    pub set: Vec<(String, Value)>,
    pub expect: Option<serde_json::Map<String, Value>>,
    pub error: bool,
    pub encode_error: bool,
    pub encoded: Option<String>,
    /// Derived robustness case: any outcome is fine as long as the decoder
    /// reports it cleanly (no crash, leak or hang).
    pub any: bool,
}

pub struct Spec {
    pub name: String,
    pub module: Module,
    pub cases: Vec<Case>,
}

pub fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("specs")
}

pub fn load_specs() -> Vec<Spec> {
    let mut paths: Vec<PathBuf> = fs::read_dir(specs_dir())
        .expect("tests/specs exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();
    paths.iter().map(|p| load_spec(p)).collect()
}

fn load_spec(path: &Path) -> Spec {
    let text = fs::read_to_string(path).unwrap();
    let json: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    let packet_file = json["spec"].as_str().expect("spec field");
    let source_path = path.parent().unwrap().join(packet_file);
    let source = fs::read_to_string(&source_path).unwrap_or_else(|e| panic!("{}: {}", source_path.display(), e));
    let module = packet_builder::compile(&source)
        .unwrap_or_else(|e| panic!("{}", e.render(&source_path.display().to_string(), &source)));

    let mut cases = Vec::new();
    for c in json["cases"].as_array().expect("cases array") {
        let hex: String = c["hex"].as_str().expect("hex").chars().filter(|c| !c.is_whitespace()).collect();
        let set = c
            .get("set")
            .and_then(|s| s.as_object())
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let case = Case {
            name: c["name"].as_str().expect("name").to_string(),
            packet: c["packet"].as_str().expect("packet").to_string(),
            hex,
            set,
            expect: c.get("expect").and_then(|e| e.as_object()).cloned(),
            error: c.get("error").and_then(|e| e.as_bool()).unwrap_or(false),
            encode_error: c.get("encode_error").and_then(|e| e.as_bool()).unwrap_or(false),
            encoded: c
                .get("encoded")
                .and_then(|e| e.as_str())
                .map(|s| s.chars().filter(|c| !c.is_whitespace()).collect()),
            any: false,
        };
        assert!(
            module.packets.iter().any(|p| p.name == case.packet),
            "{}: case {} uses unknown packet {}",
            path.display(),
            case.name,
            case.packet
        );
        cases.push(case);
    }
    let derived = derived_cases(&cases);
    cases.extend(derived);
    Spec { name: path.file_stem().unwrap().to_string_lossy().into_owned(), module, cases }
}

/// Truncated and bit-flipped variants of every vector. Decoders must handle
/// them without crashing; with sanitizers (C) and leak checks (Zig) this
/// also exercises cleanup on every error path.
fn derived_cases(cases: &[Case]) -> Vec<Case> {
    let mut out = Vec::new();
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    for c in cases.iter().filter(|c| c.set.is_empty()) {
        let bytes: Vec<u8> =
            (0..c.hex.len() / 2).map(|i| u8::from_str_radix(&c.hex[2 * i..2 * i + 2], 16).unwrap()).collect();
        let mut variants: Vec<Vec<u8>> = (0..bytes.len()).map(|n| bytes[..n].to_vec()).collect();
        for _ in 0..4 {
            if bytes.is_empty() {
                break;
            }
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut v = bytes.clone();
            let bit = (seed % (bytes.len() as u64 * 8)) as usize;
            v[bit / 8] ^= 0x80 >> (bit % 8);
            variants.push(v);
        }
        for (i, v) in variants.into_iter().enumerate() {
            out.push(Case {
                name: format!("{} (variant {})", c.name, i),
                packet: c.packet.clone(),
                hex: v.iter().map(|b| format!("{:02x}", b)).collect(),
                set: Vec::new(),
                expect: None,
                error: false,
                encode_error: false,
                encoded: None,
                any: true,
            });
        }
    }
    out
}

/// A target language as seen by the test driver.
pub trait Target {
    fn language(&self) -> Language;
    /// Returns a reason when the toolchain is missing.
    fn unavailable(&self) -> Option<String>;
    /// Program that runs every case and prints one JSON object per line.
    fn harness(&self, module: &Module, cases: &[Case]) -> String;
    /// Write `generated` and `harness` into `dir`, build, run, return stdout.
    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String>;
}

pub fn packet<'a>(module: &'a Module, name: &str) -> &'a Packet {
    module.packets.iter().find(|p| p.name == name).expect("packet exists")
}

pub fn member<'a>(p: &'a Packet, name: &str) -> &'a Member {
    p.members.iter().find(|m| m.name == name).unwrap_or_else(|| panic!("packet {} has no member {}", p.name, name))
}

/// Resolve a dotted `set` path such as `header.flags` through nested
/// (non-array) packet members: returns (owning packet, member) per segment.
pub fn resolve_path<'a>(module: &'a Module, p: &'a Packet, path: &str) -> Vec<(&'a Packet, &'a Member)> {
    let mut out = Vec::new();
    let mut cur = p;
    for seg in path.split('.') {
        let m = member(cur, seg);
        out.push((cur, m));
        if let packet_builder::ir::ValueType::Packet(n) = &m.ty {
            cur = packet(module, n);
        }
    }
    out
}

/// Accessor for a `set` path using a per-language member naming function.
pub fn accessor(module: &Module, p: &Packet, path: &str, name: impl Fn(&Packet, &Member) -> String) -> String {
    resolve_path(module, p, path).into_iter().map(|(owner, m)| name(owner, m)).collect::<Vec<_>>().join(".")
}

/// Literal for a `set` value: a number, or a double-quoted string literal
/// (valid in every target language for printable text).
pub fn set_literal(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote(s),
        other => panic!("set values must be numbers or strings, got {}", other),
    }
}

pub fn run(cmd: &mut Command, what: &str) -> Result<String, String> {
    let output = cmd.output().map_err(|e| format!("{}: cannot start {:?}: {}", what, cmd, e))?;
    if !output.status.success() {
        return Err(format!(
            "{} failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
            what,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(program)).find(|p| p.is_file())
}

pub fn work_dir(lang: Language, spec: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("codegen").join(lang.name()).join(spec);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Generate, build and run every spec for `target`, then check the results.
pub fn run_target(target: &dyn Target) {
    let lang = target.language();
    if let Some(reason) = target.unavailable() {
        if std::env::var("PB_REQUIRE_ALL").is_ok() {
            panic!("{} toolchain required (PB_REQUIRE_ALL is set): {}", lang.name(), reason);
        }
        eprintln!("skipping {} tests: {}", lang.name(), reason);
        return;
    }

    let mut failures = Vec::new();
    for spec in load_specs() {
        let dir = work_dir(lang, &spec.name);
        let opts = GenOptions::default();
        let generated = packet_builder::generate_module(&spec.module, lang, &opts);
        let harness = target.harness(&spec.module, &spec.cases);
        let stdout = match target.build_and_run(&dir, &generated, &harness) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("[{} / {}] {}", lang.name(), spec.name, e));
                continue;
            }
        };
        let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
        if lines.len() != spec.cases.len() {
            failures.push(format!(
                "[{} / {}] expected {} result lines, got {}:\n{}",
                lang.name(),
                spec.name,
                spec.cases.len(),
                lines.len(),
                stdout
            ));
            continue;
        }
        for (case, line) in spec.cases.iter().zip(lines) {
            if let Err(e) = check_case(case, line) {
                failures.push(format!("[{} / {} / {}] {}\n    output: {}", lang.name(), spec.name, case.name, e, line));
            }
        }
    }
    if !failures.is_empty() {
        panic!("{} failure(s):\n{}", failures.len(), failures.join("\n"));
    }
}

fn check_case(case: &Case, line: &str) -> Result<(), String> {
    let out: Value = serde_json::from_str(line).map_err(|e| format!("invalid JSON from harness: {}", e))?;
    let ok = out["ok"].as_bool().unwrap_or(false);
    if case.any {
        return if out.get("ok").is_some() { Ok(()) } else { Err("malformed result".into()) };
    }
    if case.error {
        return if ok { Err("expected a decode error, but decoding succeeded".into()) } else { Ok(()) };
    }
    if !ok {
        return Err(format!("decode failed: {}", out["error"]));
    }
    if let Some(expect) = &case.expect {
        for (k, v) in expect {
            let got = out["value"].get(k).ok_or_else(|| format!("member `{}` missing from output", k))?;
            if !json_eq(v, got) {
                return Err(format!("member `{}`: expected {}, got {}", k, v, got));
            }
        }
    }
    if case.encode_error {
        return if out.get("encode_error").is_some() {
            Ok(())
        } else {
            Err("expected an encode error, but encoding succeeded".into())
        };
    }
    if let Some(e) = out.get("encode_error") {
        return Err(format!("encode failed: {}", e));
    }
    let want = case.encoded.as_deref().unwrap_or(&case.hex).to_ascii_lowercase();
    let got = out["encoded"].as_str().unwrap_or("").to_ascii_lowercase();
    if want != got {
        return Err(format!("re-encoded bytes differ:\n      want {}\n      got  {}", want, got));
    }
    Ok(())
}

fn json_eq(want: &Value, got: &Value) -> bool {
    match (want, got) {
        (Value::Number(a), Value::Number(b)) => {
            if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
                return x == y;
            }
            if let (Some(x), Some(y)) = (a.as_u64(), b.as_u64()) {
                return x == y;
            }
            let (x, y) = (a.as_f64().unwrap(), b.as_f64().unwrap());
            x == y || (x - y).abs() <= 1e-9 * x.abs().max(y.abs())
        }
        (Value::String(a), Value::String(b)) => a.eq_ignore_ascii_case(b),
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| json_eq(x, y)),
        (Value::Object(a), Value::Object(b)) => a.iter().all(|(k, v)| b.get(k).map(|g| json_eq(v, g)).unwrap_or(false)),
        (a, b) => a == b,
    }
}

/// Escape a string for a double-quoted literal in C-like languages.
pub fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
