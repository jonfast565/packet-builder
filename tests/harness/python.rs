use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::python_generator::ident;
use packet_builder::ir::{Member, Module, ValueType};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct PythonTarget;

fn value_expr(m: &Member, place: &str) -> String {
    let elem = |v: &str| match &m.ty {
        ValueType::Int { .. } => format!("str({})", v),
        ValueType::Float { .. } => format!("repr(float({}))", v),
        ValueType::Mac => format!("hx({})", v),
        ValueType::Packet(n) => format!("dump_{}({})", n, v),
    };
    match &m.array {
        None => elem(place),
        Some(_) if m.ty.is_byte() => format!("hx({})", place),
        Some(_) => format!("\"[\" + \",\".join({} for x in {}) + \"]\"", elem("x"), place),
    }
}

impl Target for PythonTarget {
    fn language(&self) -> Language {
        Language::Python
    }

    fn unavailable(&self) -> Option<String> {
        which("python3").is_none().then(|| "python3 not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from("import json\nfrom packets import *\n\n");
        s.push_str("def hx(b):\n    return '\"' + bytes(b).hex() + '\"'\n\n");
        for p in &module.packets {
            let _ = writeln!(s, "def dump_{}(p):", p.name);
            s.push_str("    parts = []\n");
            for m in &p.members {
                let place = format!("p.{}", ident(&m.name));
                let _ = writeln!(s, "    parts.append('\"{}\":' + {})", m.name, value_expr(m, &place));
            }
            s.push_str("    return '{' + ','.join(parts) + '}'\n\n");
        }
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let _ = writeln!(s, "def case_{}():", i);
            s.push_str("    try:\n");
            let _ = writeln!(s, "        p = {}.decode(bytes.fromhex({}))", p.name, quote(&c.hex));
            s.push_str(
                "    except PbError as e:\n        print(json.dumps({'ok': False, 'error': str(e)}))\n        return\n",
            );
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "    p.{} = {}",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    set_literal(v)
                );
            }
            let _ = writeln!(s, "    v = dump_{}(p)", p.name);
            s.push_str("    try:\n        b = p.encode()\n");
            s.push_str("    except PbError as e:\n        print('{\"ok\":true,\"value\":' + v + ',\"encode_error\":' + json.dumps(str(e)) + '}')\n        return\n");
            s.push_str("    print('{\"ok\":true,\"value\":' + v + ',\"encoded\":' + hx(b) + '}')\n\n");
        }
        for i in 0..cases.len() {
            let _ = writeln!(s, "case_{}()", i);
        }
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.py"), generated).unwrap();
        fs::write(dir.join("main.py"), harness).unwrap();
        run(Command::new("python3").current_dir(dir).args(["-W", "error", "main.py"]), "python harness")
    }
}
