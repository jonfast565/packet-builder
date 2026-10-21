//! The reference interpreter as a test target: it runs the cases in-process,
//! so it needs no toolchain.

use std::path::Path;

use packet_builder::Language;
use packet_builder::ir::interp::{self, Value};
use packet_builder::ir::{Module, ValueType};

use super::{Case, Target, packet, resolve_path};

pub struct InterpTarget;

impl Target for InterpTarget {
    fn language(&self) -> Option<Language> {
        None
    }

    fn unavailable(&self) -> Option<String> {
        None
    }

    /// The "program" is the output itself: one JSON line per case.
    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        cases.iter().map(|c| run_case(module, c) + "\n" + &stream_case(module, c) + "\n").collect()
    }

    fn build_and_run(&self, _dir: &Path, _generated: &str, harness: &str) -> Result<String, String> {
        Ok(harness.to_string())
    }
}

fn error_json(e: &interp::Error, pre: &str) -> String {
    format!(
        "\"{0}error\":{1},\"{0}kind\":{2},\"{0}path\":{3}",
        pre,
        Value::Str(e.to_string()).to_json(),
        Value::Str(format!("{:?}", e.kind).to_lowercase()).to_json(),
        Value::Str(e.path.clone()).to_json()
    )
}

fn run_case(module: &Module, c: &Case) -> String {
    let data: Vec<u8> =
        (0..c.hex.len()).step_by(2).map(|i| u8::from_str_radix(&c.hex[i..i + 2], 16).unwrap()).collect();
    let mut value = match interp::decode_version(module, &c.packet, &data, c.version) {
        Ok(v) => v,
        Err(e) => return format!("{{\"ok\":false,{}}}", error_json(&e, "")),
    };
    for (path, v) in &c.set {
        set(module, &c.packet, &mut value, path, v);
    }
    let dumped = value.to_json();
    match interp::encode_version(module, &c.packet, &value, c.version) {
        Ok(b) => format!("{{\"ok\":true,\"value\":{},\"encoded\":{}}}", dumped, Value::Bytes(b).to_json()),
        Err(e) => format!("{{\"ok\":true,\"value\":{},{}}}", dumped, error_json(&e, "encode_")),
    }
}

/// What a stream decoder sees: the bytes taken or still needed, and the
/// frame length from the header.
fn stream_case(module: &Module, c: &Case) -> String {
    let data: Vec<u8> =
        (0..c.hex.len()).step_by(2).map(|i| u8::from_str_radix(&c.hex[i..i + 2], 16).unwrap()).collect();
    let mut r = interp::Reader::new(&data);
    if let Some((v, min, latest)) = c.versions(module) {
        let _ = r.set_version(v as i64, min, latest);
    }
    let mut line = match interp::decode_from(module, &c.packet, &mut r) {
        Ok(_) => format!("{{\"try\":\"done\",\"n\":{}", r.position_bits().div_ceil(8)),
        Err(e) if e.kind == interp::ErrorKind::Incomplete => {
            format!("{{\"try\":\"incomplete\",\"n\":{}", e.needed_bits.div_ceil(8).max(1))
        }
        Err(_) => "{\"try\":\"error\"".to_string(),
    };
    let p = packet(module, &c.packet);
    if let (true, Some(f)) = (super::has_frame(module, p), module.frame_length(p)) {
        let frame = match interp::frame_length(module, p, &f, &data) {
            Ok(n) if n >= 0 => n.to_string(),
            Ok(_) => "\"error\"".into(),
            Err(e) if e.kind == interp::ErrorKind::Incomplete => "null".into(),
            Err(_) => "\"error\"".into(),
        };
        line.push_str(&format!(",\"frame\":{}", frame));
    }
    line + "}"
}

/// Overwrite the member at a dotted path with a JSON number or string.
fn set(module: &Module, packet_name: &str, value: &mut Value, path: &str, v: &serde_json::Value) {
    let segments = resolve_path(module, packet(module, packet_name), path);
    let mut cur = value;
    for (_, m) in &segments {
        let Value::Struct(s) = cur else { panic!("{} is not a packet", path) };
        cur = s.get_mut(&m.name).expect("member exists");
    }
    let m = segments.last().unwrap().1;
    *cur = match (&m.ty, v) {
        (_, serde_json::Value::String(s)) => Value::Str(s.clone()),
        (ValueType::Float { .. }, n) => Value::Float(n.as_f64().unwrap()),
        (_, n) => Value::Int(n.as_i64().map(|x| x as i128).or(n.as_u64().map(|x| x as i128)).unwrap()),
    };
}
