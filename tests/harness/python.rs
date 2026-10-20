use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::python::ident;
use packet_builder::ir::Module;

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct PythonTarget;

impl Target for PythonTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Python)
    }

    fn unavailable(&self) -> Option<String> {
        which("python3").is_none().then(|| "python3 not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("import json\nfrom packets import *\n\n");
        s.push_str("def pb_e(e, pre):\n    return ',' + ','.join('\"%s%s\":%s' % (pre, k, json.dumps(v)) for k, v in (('error', str(e)), ('kind', e.kind), ('path', e.path)))\n\n");
        s.push_str("def hx(b):\n    return '\"' + bytes(b).hex() + '\"'\n\n");
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let _ = writeln!(s, "def case_{}():", i);
            s.push_str("    try:\n");
            let _ = writeln!(s, "        p = {}.decode(bytes.fromhex({}))", p.name, quote(&c.hex));
            s.push_str(
                "    except PbError as e:\n        print('{\"ok\":false' + pb_e(e, '') + '}')\n        return\n",
            );
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "    p.{} = {}",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    set_literal(v)
                );
            }
            s.push_str("    v = p.to_json()\n");
            s.push_str("    try:\n        b = p.encode()\n");
            s.push_str("    except PbError as e:\n        print('{\"ok\":true,\"value\":' + v + pb_e(e, 'encode_') + '}')\n        return\n");
            s.push_str("    print('{\"ok\":true,\"value\":' + v + ',\"encoded\":' + hx(b) + '}')\n\n");
            let _ = writeln!(s, "def stream_{}():", i);
            let _ = writeln!(s, "    d = bytes.fromhex({})", quote(&c.hex));
            s.push_str("    try:\n");
            let _ = writeln!(s, "        p, n = {}.try_decode(d)", p.name);
            s.push_str("        s = '{\"try\":\"%s\",\"n\":%d' % (\"done\" if p is not None else \"incomplete\", n)\n");
            s.push_str("    except PbError:\n        s = '{\"try\":\"error\"'\n");
            if super::has_frame(module, p) {
                s.push_str("    try:\n");
                let _ = writeln!(s, "        f = {}.frame_len(d)", p.name);
                s.push_str("        s += ',\"frame\":' + ('null' if f is None else str(f))\n");
                s.push_str("    except PbError:\n        s += ',\"frame\":\"error\"'\n");
            }
            s.push_str("    print(s + '}')\n\n");
        }
        for i in 0..cases.len() {
            let _ = writeln!(s, "case_{}()", i);
            let _ = writeln!(s, "stream_{}()", i);
        }
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.py"), generated).unwrap();
        fs::write(dir.join("main.py"), harness).unwrap();
        run(Command::new("python3").current_dir(dir).args(["-W", "error", "main.py"]), "python harness")
    }
}
