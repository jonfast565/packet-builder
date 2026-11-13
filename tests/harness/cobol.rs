//! COBOL: the generated file is a whole program. Its main program reads a
//! `.dat` file with one case per line (`<Packet> <hex or -> [@version]
//! [!argument]... [%program] [path=integer | path=#hex]...`) and prints the two JSON lines per case.
//! A source case (`%HX-SRC-<n>`) is decoded through a source that program
//! sets up: `HX-FETCH` serves the line's bytes in pages and refuses the
//! case's unread range. Those programs follow the `.dat` lines, after a
//! `*>@programs` line, and are compiled with the generated file.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::Language;
use packet_builder::ir::Module;
use serde_json::Value;

use super::{Case, Target, run, which};

pub struct CobolTarget;

/// Where the test programs start in what `harness` returns.
const PROGRAMS: &str = "*>@programs\n";

/// The fetch program of source cases: the bytes come from `HX-STATE`,
/// which a case's `HX-SRC-<n>` fills.
const FETCH: &str = r#"IDENTIFICATION DIVISION.
PROGRAM-ID. HX-FETCH.
DATA DIVISION.
WORKING-STORAGE SECTION.
@STATE@
PROCEDURE DIVISION.
    IF FUNCTION MAX(PB-SF-AT HX-FROM) < FUNCTION MIN(PB-SF-AT + PB-SF-N HX-TO)
        MOVE 1 TO PB-SF-RC
        MOVE "fetched an unread byte" TO PB-SF-MSG
        GOBACK
    END-IF
    MOVE HX-DATA(PB-SF-AT + 1:PB-SF-N) TO PB-IN(PB-SF-AT + 1:PB-SF-N)
    GOBACK.
END PROGRAM HX-FETCH.
"#;

/// `PB-STATE` (from the runtime) and the test programs' own record.
fn state() -> String {
    let rt = include_str!("../../runtime/cobol.cob");
    let start = rt.find("*>@state{\n").expect("state start") + "*>@state{\n".len();
    let end = rt.find("*>@state}").expect("state end");
    format!(
        "{}01 HX-STATE EXTERNAL.\n   05 HX-FROM BINARY-DOUBLE SIGNED.\n   05 HX-TO BINARY-DOUBLE SIGNED.\n   05 HX-DATA PIC X(65537).\n",
        &rt[start..end]
    )
}

/// The program that sets up the source of case `n`: it keeps the line's
/// bytes for `HX-FETCH` and opens a source over them.
fn source_program(n: usize, c: &Case) -> String {
    let (from, to) = c.unread.unwrap_or((0, 0));
    format!(
        "IDENTIFICATION DIVISION.\nPROGRAM-ID. HX-SRC-{n}.\nDATA DIVISION.\nWORKING-STORAGE SECTION.\n@STATE@\nPROCEDURE DIVISION.\n    IF PB-LEN > 0\n        MOVE PB-IN(1:PB-LEN) TO HX-DATA(1:PB-LEN)\n    END-IF\n    MOVE {from} TO HX-FROM\n    MOVE {to} TO HX-TO\n    MOVE \"HX-FETCH\" TO PB-SFETCH\n    MOVE {page} TO PB-A1\n    CALL \"PB-SOPEN\"\n    GOBACK.\nEND PROGRAM HX-SRC-{n}.\n",
        page = super::SOURCE_PAGE
    )
}

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
        let mut programs = String::new();
        for (n, c) in cases.iter().enumerate() {
            let hex: String = c.hex.chars().filter(|ch| !ch.is_whitespace()).collect();
            let _ = write!(s, "{} {}", c.packet, if hex.is_empty() { "-" } else { &hex });
            if let Some(v) = c.version {
                let _ = write!(s, " @{}", v);
            }
            for a in &c.args {
                let _ = write!(s, " !{}", a);
            }
            if c.source {
                let _ = write!(s, " %HX-SRC-{}", n);
                if programs.is_empty() {
                    programs.push_str(FETCH);
                }
                programs.push_str(&source_program(n, c));
            }
            for (path, v) in &c.set {
                let _ = write!(s, " {}={}", path, set_value(v));
            }
            s.push('\n');
        }
        if !programs.is_empty() {
            s.push_str(PROGRAMS);
            s.push_str(&programs.replace("@STATE@\n", &state()));
        }
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.cob"), generated).unwrap();
        let (cases, programs) = harness.split_once(PROGRAMS).unwrap_or((harness, ""));
        fs::write(dir.join("cases.dat"), cases).unwrap();
        let cobc = cobc().expect("cobc is available");
        let mut args = vec!["-free", "-x", "-o", "packets", "packets.cob"];
        if !programs.is_empty() {
            fs::write(dir.join("sources.cob"), programs).unwrap();
            args.push("sources.cob");
        }
        run(Command::new(cobc).current_dir(dir).args(&args), "cobc")?;
        run(Command::new(dir.join("packets")).current_dir(dir).arg("cases.dat"), "cobol program")
    }
}
