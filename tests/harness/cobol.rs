//! COBOL: the generated file is a whole program. Its main program reads a
//! `.dat` file with one case per line (`<Packet> <hex or -> [@version]
//! [!argument]... [path=integer | path=#hex]...`) and prints the two JSON lines per case.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::Language;
use packet_builder::ir::Module;
use serde_json::Value;

use super::{Case, Target, run, which};

pub struct CobolTarget;

/// `cobc`: `$COBC`, or the one on the PATH.
fn cobc() -> Option<PathBuf> {
    match std::env::var_os("COBC") {
        Some(p) => Some(PathBuf::from(p)).filter(|p| p.is_file()),
        None => which("cobc"),
    }
}

fn set_value(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("#{}", s.bytes().map(|b| format!("{:02x}", b)).collect::<String>()),
        other => panic!("set values must be numbers or strings, got {}", other),
    }
}

impl Target for CobolTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Cobol)
    }

    fn unavailable(&self) -> Option<String> {
        cobc().is_none().then(|| "cobc (GnuCOBOL) not found (set $COBC)".into())
    }

    fn harness(&self, _module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("* packet-builder test vectors\n");
        for c in cases {
            let hex: String = c.hex.chars().filter(|ch| !ch.is_whitespace()).collect();
            let _ = write!(s, "{} {}", c.packet, if hex.is_empty() { "-" } else { &hex });
            if let Some(v) = c.version {
                let _ = write!(s, " @{}", v);
            }
            for a in &c.args {
                let _ = write!(s, " !{}", a);
            }
            for (path, v) in &c.set {
                let _ = write!(s, " {}={}", path, set_value(v));
            }
            s.push('\n');
        }
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.cob"), generated).unwrap();
        fs::write(dir.join("cases.dat"), harness).unwrap();
        let cobc = cobc().expect("cobc is available");
        run(Command::new(cobc).current_dir(dir).args(["-free", "-x", "-o", "packets", "packets.cob"]), "cobc")?;
        run(Command::new(dir.join("packets")).current_dir(dir).arg("cases.dat"), "cobol program")
    }
}
