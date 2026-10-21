use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::rust::ident;
use packet_builder::ir::Module;

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct RustTarget;

impl Target for RustTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Rust)
    }

    fn unavailable(&self) -> Option<String> {
        which("rustc").is_none().then(|| "rustc not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("#![allow(non_snake_case)]\nmod packets;\nuse packets::*;\n\n");
        s.push_str("fn pb_hex(b: &[u8]) -> String { format!(\"\\\"{}\\\"\", b.iter().map(|x| format!(\"{:02x}\", x)).collect::<String>()) }\n");
        s.push_str("fn pb_unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }\n");
        s.push_str("fn pb_q(s: &str) -> String {\n    let mut o = String::from(\"\\\"\");\n    for c in s.chars() {\n        match c {\n            '\"' => o.push_str(\"\\\\\\\"\"),\n            '\\\\' => o.push_str(\"\\\\\\\\\"),\n            c if (c as u32) < 0x20 => o.push_str(&format!(\"\\\\u{:04x}\", c as u32)),\n            c => o.push(c),\n        }\n    }\n    o.push('\"');\n    o\n}\n\n");
        s.push_str(
            r#"fn pb_e(e: &PbError, pre: &str) -> String {
    format!("\"{0}error\":{1},\"{0}kind\":{2},\"{0}path\":{3}", pre, pb_q(&e.to_string()),
        pb_q(&format!("{:?}", e.kind).to_lowercase()), pb_q(&e.path))
}

"#,
        );
        s.push_str("fn main() {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            match c.version {
                Some(v) => {
                    let _ = writeln!(s, "    match {}::decode_v(&pb_unhex({}), {}) {{", p.name, quote(&c.hex), v);
                }
                None => {
                    let _ = writeln!(s, "    match {}::decode(&pb_unhex({})) {{", p.name, quote(&c.hex));
                }
            }
            s.push_str("        Err(e) => println!(\"{{\\\"ok\\\":false,{}}}\", pb_e(&e, \"\")),\n");
            s.push_str("        Ok(mut p) => {\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "            p.{} = {};",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    if v.is_string() { format!("{}.to_string().into()", set_literal(v)) } else { set_literal(v) }
                );
            }
            s.push_str("            let v = p.to_json();\n");
            match c.version {
                Some(v) => {
                    let _ = writeln!(s, "            match p.encode_v({}) {{", v);
                }
                None => s.push_str("            match p.encode() {\n"),
            }
            s.push_str("                Ok(b) => println!(\"{{\\\"ok\\\":true,\\\"value\\\":{},\\\"encoded\\\":{}}}\", v, pb_hex(&b)),\n");
            s.push_str("                Err(e) => println!(\"{{\\\"ok\\\":true,\\\"value\\\":{},{}}}\", v, pb_e(&e, \"encode_\")),\n");
            s.push_str("            }\n        }\n    }\n");
            let _ = writeln!(s, "    {{\n        let d = pb_unhex({});", quote(&c.hex));
            match c.version {
                Some(v) => {
                    let _ = writeln!(s, "        let mut s = match {}::try_decode_v(&d, {}) {{", p.name, v);
                }
                None => {
                    let _ = writeln!(s, "        let mut s = match {}::try_decode(&d) {{", p.name);
                }
            }
            s.push_str(
                "            Ok(PbStatus::Done(_, n)) => format!(\"{{\\\"try\\\":\\\"done\\\",\\\"n\\\":{}\", n),\n",
            );
            s.push_str("            Ok(PbStatus::Incomplete(n)) => format!(\"{{\\\"try\\\":\\\"incomplete\\\",\\\"n\\\":{}\", n),\n");
            s.push_str("            Err(_) => \"{\\\"try\\\":\\\"error\\\"\".to_string(),\n        };\n");
            if super::has_frame(module, p) {
                let _ = writeln!(s, "        s += &match {}::frame_len(&d) {{", p.name);
                s.push_str("            Ok(Some(n)) => format!(\",\\\"frame\\\":{}\", n),\n");
                s.push_str("            Ok(None) => \",\\\"frame\\\":null\".to_string(),\n");
                s.push_str("            Err(_) => \",\\\"frame\\\":\\\"error\\\"\".to_string(),\n        };\n");
            }
            s.push_str("        println!(\"{}}}\", s);\n    }\n");
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
                "2024",
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
