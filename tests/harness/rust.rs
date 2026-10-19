use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::rust_generator::ident;
use packet_builder::ir::{Member, Module, ValueType};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct RustTarget;

fn value_expr(m: &Member, place: &str) -> String {
    let elem = |v: &str| match &m.ty {
        ValueType::Int { .. } => format!("format!(\"{{}}\", {})", v),
        ValueType::Float { .. } => format!("format!(\"{{:?}}\", {})", v),
        ValueType::Mac => format!("pb_hex(&{})", v),
        ValueType::Packet(n) => format!("dump_{}(&{})", n, v),
    };
    match &m.array {
        None => elem(place),
        Some(_) if m.ty.is_byte() => format!("pb_hex(&{})", place),
        Some(_) => format!(
            "format!(\"[{{}}]\", {}.iter().map(|x| {}).collect::<Vec<_>>().join(\",\"))",
            place,
            elem("*x").replace("&*x", "x")
        ),
    }
}

impl Target for RustTarget {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn unavailable(&self) -> Option<String> {
        which("rustc").is_none().then(|| "rustc not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from("#![allow(non_snake_case)]\nmod packets;\nuse packets::*;\n\n");
        s.push_str("fn pb_hex(b: &[u8]) -> String { format!(\"\\\"{}\\\"\", b.iter().map(|x| format!(\"{:02x}\", x)).collect::<String>()) }\n");
        s.push_str("fn pb_unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }\n");
        s.push_str("fn pb_q(s: &str) -> String { format!(\"{:?}\", s) }\n\n");
        for p in &module.packets {
            let _ = writeln!(s, "fn dump_{}(p: &{}) -> String {{", p.name, p.name);
            s.push_str("    let mut parts: Vec<String> = Vec::new();\n");
            for m in &p.members {
                let place = format!("p.{}", ident(&m.name));
                let _ = writeln!(s, "    parts.push(format!(\"\\\"{}\\\":{{}}\", {}));", m.name, value_expr(m, &place));
            }
            s.push_str("    format!(\"{{{}}}\", parts.join(\",\"))\n}\n\n");
        }
        s.push_str("fn main() {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            let _ = writeln!(s, "    match {}::decode(&pb_unhex({})) {{", p.name, quote(&c.hex));
            s.push_str("        Err(e) => println!(\"{{\\\"ok\\\":false,\\\"error\\\":{}}}\", pb_q(&e.0)),\n");
            s.push_str("        Ok(mut p) => {\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "            p.{} = {};",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    set_literal(v)
                );
            }
            let _ = writeln!(s, "            let v = dump_{}(&p);", p.name);
            s.push_str("            match p.encode() {\n");
            s.push_str("                Ok(b) => println!(\"{{\\\"ok\\\":true,\\\"value\\\":{},\\\"encoded\\\":{}}}\", v, pb_hex(&b)),\n");
            s.push_str("                Err(e) => println!(\"{{\\\"ok\\\":true,\\\"value\\\":{},\\\"encode_error\\\":{}}}\", v, pb_q(&e.0)),\n");
            s.push_str("            }\n        }\n    }\n");
        }
        s.push_str("}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.rs"), generated).unwrap();
        fs::write(dir.join("main.rs"), harness).unwrap();
        // Debug build: integer overflow in generated code panics.
        run(
            Command::new("rustc").current_dir(dir).args([
                "--edition",
                "2021",
                "-D",
                "warnings",
                "-A",
                "unused",
                "main.rs",
                "-o",
                "harness",
            ]),
            "rustc",
        )?;
        run(&mut Command::new(dir.join("harness")), "rust harness")
    }
}
