//! The generated Wireshark dissectors, run with tshark over every spec
//! vector. Each spec's vectors go into one pcap (link type USER0), one frame
//! per case: a byte saying which packet, then the case's bytes. A small
//! wrapper protocol picks the packet and calls the generated dissector.
//!
//! For each frame: decoded values from the spec's `expect` must appear as
//! field values; failing vectors must produce an expert item; and no frame,
//! truncated and bit-flipped variants included, may hit a Lua error.
//! Skipped when tshark is missing, unless PB_REQUIRE_ALL is set.

#[allow(dead_code)]
mod harness;

use std::collections::HashMap;
use std::fs;
use std::process::Command;

use harness::{Case, Spec, load_specs, which, work_dir};
use packet_builder::generate_dissector;
use packet_builder::ir::{Module, Packet, ValueType};
use serde_json::Value;

/// Every field value of one frame, by field name.
type Fields = HashMap<String, Vec<String>>;

fn collect(v: &Value, out: &mut Fields) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                match v {
                    Value::String(s) => out.entry(k.clone()).or_default().push(s.clone()),
                    Value::Array(items) => {
                        for item in items {
                            match item {
                                Value::String(s) => out.entry(k.clone()).or_default().push(s.clone()),
                                other => collect(other, out),
                            }
                        }
                    }
                    other => collect(other, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|i| collect(i, out)),
        _ => {}
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A shown integer (`10`, `0x0a`, `-3`) as a number.
fn number(s: &str) -> Option<i128> {
    match s.strip_prefix("0x") {
        Some(h) => i128::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Check that `field` shows `want` (an integer, bytes as hex, or a string).
fn expect_value(fields: &Fields, field: &str, ty: &ValueType, bytes: bool, want: &Value, errors: &mut Vec<String>) {
    let got = fields.get(field).cloned().unwrap_or_default();
    let ok = match (ty, want) {
        _ if bytes || matches!(ty, ValueType::Mac) => {
            let w = want.as_str().unwrap_or("").to_ascii_lowercase();
            got.iter().any(|g| g.replace(':', "").to_ascii_lowercase() == w)
        }
        (ValueType::Int { .. }, Value::Number(n)) => {
            let w = n.as_i64().map(|v| v as i128).or_else(|| n.as_u64().map(|v| v as i128));
            got.iter().any(|g| number(g) == w || number(g).zip(w).is_some_and(|(a, b)| a as u64 == b as u64))
        }
        (ValueType::Str, Value::String(s)) => got.iter().any(|g| g == s) || !s.is_ascii(),
        _ => true,
    };
    if !ok {
        errors.push(format!("{} should show {} (shown: {:?})", field, want, got));
    }
}

/// Walk an expected value of packet `p`, checking every field it names.
fn expect_packet(
    m: &Module,
    p: &Packet,
    want: &serde_json::Map<String, Value>,
    fields: &Fields,
    errors: &mut Vec<String>,
) {
    for (name, v) in want {
        let Some(member) = p.members.iter().find(|x| &x.name == name) else { continue };
        let field = format!("pbtest.{}.{}", p.name.to_ascii_lowercase(), name.to_ascii_lowercase());
        // A member that exists in some versions only is not in the tree of
        // a frame of another version (where it keeps its default).
        if member.present.is_some() && !fields.contains_key(&field) && (v == &Value::from(0) || v == &Value::from("")) {
            continue;
        }
        let bytes = member.array.is_some() && member.ty.is_byte();
        match (&member.ty, v) {
            (ValueType::Packet(n), Value::Object(o)) => expect_packet(m, harness::packet(m, n), o, fields, errors),
            (ValueType::Packet(n), Value::Array(items)) => {
                for item in items.iter().filter_map(|i| i.as_object()) {
                    expect_packet(m, harness::packet(m, n), item, fields, errors);
                }
            }
            (ValueType::Union(u), Value::Object(o)) => {
                let (Some(kind), Some(u)) = (o.get("kind").and_then(|k| k.as_str()), m.union(u)) else { continue };
                let Some(arm) = u.arms.iter().find(|a| a.name == kind) else { continue };
                let value = o.get("value").unwrap_or(&Value::Null);
                let arm_field = format!("pbtest.{}.{}", u.name.to_ascii_lowercase(), kind.to_ascii_lowercase());
                match (&arm.ty, value) {
                    (Some(ValueType::Packet(n)), Value::Object(inner)) => {
                        expect_packet(m, harness::packet(m, n), inner, fields, errors)
                    }
                    (Some(ty), v) if !v.is_null() => expect_value(fields, &arm_field, ty, arm.is_bytes(), v, errors),
                    _ => {}
                }
            }
            (ty, Value::Array(items)) if !bytes => {
                for item in items {
                    expect_value(fields, &field, ty, false, item, errors);
                }
            }
            (ty, v) => expect_value(fields, &field, ty, bytes, v, errors),
        }
    }
}

/// Run one spec through tshark; returns the problems found.
fn run_spec(tshark: &str, spec: &Spec) -> Vec<String> {
    let dir = work_dir("wireshark", &spec.name);
    let names: Vec<&str> = {
        let mut n: Vec<&str> = spec.cases.iter().map(|c| c.packet.as_str()).collect();
        n.sort();
        n.dedup();
        n
    };
    // No protocol of its own: the wrapper registers one.
    let package = format!("spec_{}", spec.name);
    fs::write(dir.join("gen.lua"), generate_dissector(&spec.module, &[], &package)).unwrap();
    let table: Vec<String> = names.iter().enumerate().map(|(i, n)| format!("[{}] = \"{}\"", i, n)).collect();
    // Frames start with the packet's index, and for files with versions the
    // version the case gives (0: none).
    let versioned = spec.module.versions.is_some();
    let skip = if versioned { 2 } else { 1 };
    let call = if versioned {
        "M.dissect(names[tvb(0, 1):uint()], F, X, rest, item, tvb(1, 1):uint())"
    } else {
        "M.dissect(names[tvb(0, 1):uint()], F, X, rest, item)"
    };
    let wrapper = format!(
        r#"local M = dofile("{gen}")
local names = {{ {table} }}
local proto, F, X = M.register("pbtest", "PB test", names[0])
function proto.dissector(tvb, pinfo, tree)
  local item = tree:add(proto, tvb())
  local rest = tvb:len() > {skip} and tvb({skip}):tvb() or ByteArray.new():tvb("empty")
  {call}
end
"#,
        gen = dir.join("gen.lua").display(),
        table = table.join(", ")
    );
    fs::write(dir.join("wrap.lua"), wrapper).unwrap();

    // The pcap: one frame per case.
    let mut pcap = Vec::new();
    for v in [0xa1b2c3d4u32.to_le_bytes(), [2, 0, 4, 0], [0; 4], [0; 4], 65535u32.to_le_bytes(), 147u32.to_le_bytes()] {
        pcap.extend_from_slice(&v);
    }
    let cases: Vec<&Case> = spec.cases.iter().collect();
    for c in &cases {
        let mut frame = vec![names.iter().position(|n| *n == c.packet).unwrap() as u8];
        if versioned {
            frame.push(c.version.unwrap_or(0) as u8);
        }
        frame.extend(hex(&c.hex));
        for v in [0u32, 0, frame.len() as u32, frame.len() as u32] {
            pcap.extend_from_slice(&v.to_le_bytes());
        }
        pcap.extend_from_slice(&frame);
    }
    fs::write(dir.join("cases.pcap"), &pcap).unwrap();

    let output = Command::new(tshark)
        .arg("-X")
        .arg(format!("lua_script:{}", dir.join("wrap.lua").display()))
        .args(["-o", r#"uat:user_dlts:"User 0 (DLT=147)","pbtest","0","","0","""#])
        .arg("-r")
        .arg(dir.join("cases.pcap"))
        .args(["-T", "json", "--no-duplicate-keys"])
        .output()
        .expect("run tshark");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() || stderr.contains("Lua") {
        return vec![format!("[{}] tshark failed ({}):\n{}", spec.name, output.status, stderr)];
    }
    // Deeply nested packets nest deeply in the JSON too.
    let mut de = serde_json::Deserializer::from_str(&stdout);
    de.disable_recursion_limit();
    let frames: Vec<Value> = match serde::Deserialize::deserialize(&mut de) {
        Ok(v) => v,
        Err(e) => return vec![format!("[{}] bad tshark JSON: {}", spec.name, e)],
    };
    let mut problems = Vec::new();
    for (case, frame) in cases.iter().zip(&frames) {
        let mut fields = Fields::new();
        collect(&frame["_source"]["layers"], &mut fields);
        let mut errors = Vec::new();
        let text = frame.to_string();
        if text.contains("packet-builder internal error") || text.contains("Lua Error") {
            errors.push(format!("Lua error: {}", text));
        }
        let expert = fields.contains_key("_ws.expert.message") || fields.contains_key("_ws.malformed");
        if case.error && !expert {
            errors.push("a failing vector should produce an expert item".into());
        }
        if let (Some(want), false) = (&case.expect, case.any || case.error) {
            expect_packet(&spec.module, harness::packet(&spec.module, &case.packet), want, &fields, &mut errors);
        }
        for e in errors {
            problems.push(format!("[{} / {}] {}", spec.name, case.name, e));
        }
    }
    if frames.len() != cases.len() {
        problems.push(format!("[{}] tshark showed {} of {} frames", spec.name, frames.len(), cases.len()));
    }
    problems
}

#[test]
fn dissectors_work_in_tshark() {
    let Some(tshark) = which("tshark") else {
        assert!(std::env::var("PB_REQUIRE_ALL").is_err(), "tshark not found on PATH");
        eprintln!("skipping: tshark not found on PATH");
        return;
    };
    let tshark = tshark.display().to_string();
    let mut problems = Vec::new();
    for spec in load_specs() {
        problems.extend(run_spec(&tshark, &spec));
    }
    assert!(problems.is_empty(), "{} problem(s):\n{}", problems.len(), problems.join("\n"));
}

/// An Ethernet/IPv4/TCP frame from port 40000 to 5190 carrying `payload`
/// at sequence number `seq`.
fn tcp_frame(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
    let total = (20 + 20 + payload.len()) as u16;
    f.extend([0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
    f.extend(40000u16.to_be_bytes());
    f.extend(5190u16.to_be_bytes());
    f.extend(seq.to_be_bytes());
    f.extend([0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

#[test]
fn oscar_over_tcp_is_reassembled() {
    let Some(tshark) = which("tshark") else {
        assert!(std::env::var("PB_REQUIRE_ALL").is_err(), "tshark not found on PATH");
        return;
    };
    let module = packet_builder::compile_file(std::path::Path::new("examples/oscar.packet")).unwrap();
    let dir = work_dir("wireshark", "oscar-tcp");
    fs::write(dir.join("oscar.lua"), generate_dissector(&module, &module.dissectors, "oscar")).unwrap();
    let stream = hex(concat!(
        "2a011f3a000400000001",
        "2a021f3b0018000100030000000000000001000200030004000900130015",
        "2a021f3c004c000400070000",
        "0000002f313233343536373800010961696d6275646479310019000200010002",
        "0010000300043b9aca00000200180501000101010100",
        "0f0000000048656c6c6f2c2041494d21",
    ));
    // The second FLAP is split across the two segments; the third FLAP
    // starts in the second one.
    let mut pcap = Vec::new();
    for v in [0xa1b2c3d4u32.to_le_bytes(), [2, 0, 4, 0], [0; 4], [0; 4], 65535u32.to_le_bytes(), 1u32.to_le_bytes()] {
        pcap.extend_from_slice(&v);
    }
    for (seq, part) in [(1u32, &stream[..25]), (26, &stream[25..])] {
        let frame = tcp_frame(seq, part);
        for v in [0u32, 0, frame.len() as u32, frame.len() as u32] {
            pcap.extend_from_slice(&v.to_le_bytes());
        }
        pcap.extend_from_slice(&frame);
    }
    fs::write(dir.join("oscar.pcap"), &pcap).unwrap();
    let output = Command::new(tshark)
        .arg("-X")
        .arg(format!("lua_script:{}", dir.join("oscar.lua").display()))
        .arg("-r")
        .arg(dir.join("oscar.pcap"))
        .args(["-T", "fields", "-e", "oscar.flap.channel", "-e", "oscar.icbmreceive.screen_name"])
        .output()
        .expect("run tshark");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success() && !stderr.contains("Lua"), "{}", stderr);
    // Frame 1 holds the first FLAP; frame 2 the rest of the second and the third.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", stdout);
    assert_eq!(lines[0].split('\t').next(), Some("1"), "{}", stdout);
    assert_eq!(lines[1], "2,2\taimbuddy1", "{}", stdout);
}

/// An Ethernet/IPv4/UDP frame to port 31337 carrying `payload`.
fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
    let total = (20 + 8 + payload.len()) as u16;
    f.extend([0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
    f.extend(40000u16.to_be_bytes());
    f.extend(31337u16.to_be_bytes());
    f.extend((8 + payload.len() as u16).to_be_bytes());
    f.extend([0, 0]);
    f.extend_from_slice(payload);
    f
}

#[test]
fn heuristic_dissectors_check_magic_values() {
    let Some(tshark) = which("tshark") else {
        assert!(std::env::var("PB_REQUIRE_ALL").is_err(), "tshark not found on PATH");
        return;
    };
    let src = "packet Hello be { magic uint32 == 0x50425431, n uint8 }\n\
               dissector Hello { name \"Hello\", abbrev \"hello\", heuristic }";
    let module = packet_builder::compile(src).unwrap();
    let dir = work_dir("wireshark", "heuristic");
    fs::write(dir.join("hello.lua"), generate_dissector(&module, &module.dissectors, "hello")).unwrap();
    let mut pcap = Vec::new();
    for v in [0xa1b2c3d4u32.to_le_bytes(), [2, 0, 4, 0], [0; 4], [0; 4], 65535u32.to_le_bytes(), 1u32.to_le_bytes()] {
        pcap.extend_from_slice(&v);
    }
    for payload in [hex("5042543107"), hex("0000000007")] {
        let frame = udp_frame(&payload);
        for v in [0u32, 0, frame.len() as u32, frame.len() as u32] {
            pcap.extend_from_slice(&v.to_le_bytes());
        }
        pcap.extend_from_slice(&frame);
    }
    fs::write(dir.join("hello.pcap"), &pcap).unwrap();
    let output = Command::new(tshark)
        .arg("-X")
        .arg(format!("lua_script:{}", dir.join("hello.lua").display()))
        .arg("-r")
        .arg(dir.join("hello.pcap"))
        .args(["-T", "fields", "-e", "hello.hello.n"])
        .output()
        .expect("run tshark");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(stdout.lines().collect::<Vec<_>>(), ["7", ""], "{}", stdout);
}
