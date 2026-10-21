use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::go::field_name;
use packet_builder::ir::Module;

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct GoTarget;

impl Target for GoTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Go)
    }

    fn unavailable(&self) -> Option<String> {
        which("go").is_none().then(|| "go not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from(
            "package main\n\nimport (\n\t\"encoding/hex\"\n\t\"encoding/json\"\n\t\"fmt\"\n\t\"strconv\"\n\t\"strings\"\n\n\t. \"harness/packets\"\n)\n\n",
        );
        s.push_str("var _ = strings.Join\n\n");
        s.push_str("func js(v string) string { b, _ := json.Marshal(v); return string(b) }\n\n");
        s.push_str("func pbE(err error, pre string) string {\n\te := err.(*PbError)\n\treturn fmt.Sprintf(\"\\\"%serror\\\":%s,\\\"%skind\\\":%s,\\\"%spath\\\":%s\", pre, strconv.Quote(e.Error()), pre, js(e.Kind.String()), pre, js(e.Path))\n}\n\n");
        s.push_str("func hx(b []byte) string { return \"\\\"\" + hex.EncodeToString(b) + \"\\\"\" }\n\n");
        s.push_str("func main() {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            s.push_str("\tfunc() {\n");
            let _ = writeln!(s, "\t\tdata, _ := hex.DecodeString({})", quote(&c.hex));
            match c.version {
                Some(v) => {
                    let _ = writeln!(s, "\t\tp, err := Decode{}V(data, {})", p.name, v);
                }
                None => {
                    let _ = writeln!(s, "\t\tp, err := Decode{}(data)", p.name);
                }
            }
            s.push_str("\t\tif err != nil {\n\t\t\tfmt.Printf(\"{\\\"ok\\\":false,%s}\\n\", pbE(err, \"\"))\n\t\t\treturn\n\t\t}\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "\t\tp.{} = {}",
                    super::accessor(module, p, name, |_, m| field_name(&m.name)),
                    set_literal(v)
                );
            }
            s.push_str("\t\tv := p.ToJSON()\n");
            match c.version {
                Some(v) => {
                    let _ = writeln!(s, "\t\tb, err := p.EncodeV({})", v);
                }
                None => s.push_str("\t\tb, err := p.Encode()\n"),
            }
            s.push_str("\t\tif err != nil {\n\t\t\tfmt.Printf(\"{\\\"ok\\\":true,\\\"value\\\":%s,%s}\\n\", v, pbE(err, \"encode_\"))\n\t\t\treturn\n\t\t}\n");
            s.push_str("\t\tfmt.Printf(\"{\\\"ok\\\":true,\\\"value\\\":%s,\\\"encoded\\\":%s}\\n\", v, hx(b))\n");
            s.push_str("\t}()\n");
            s.push_str("\tfunc() {\n");
            let _ = writeln!(s, "\t\tdata, _ := hex.DecodeString({})", quote(&c.hex));
            s.push_str("\t\ts := \"\"\n");
            match c.version {
                Some(v) => {
                    let _ = writeln!(s, "\t\tif p, n, err := TryDecode{}V(data, {}); err != nil {{", p.name, v);
                }
                None => {
                    let _ = writeln!(s, "\t\tif p, n, err := TryDecode{}(data); err != nil {{", p.name);
                }
            }
            s.push_str("\t\t\ts = `{\"try\":\"error\"`\n\t\t} else if p == nil {\n\t\t\ts = fmt.Sprintf(`{\"try\":\"incomplete\",\"n\":%d`, n)\n\t\t} else {\n\t\t\ts = fmt.Sprintf(`{\"try\":\"done\",\"n\":%d`, n)\n\t\t}\n");
            if super::has_frame(module, p) {
                let _ = writeln!(s, "\t\tif size, ok, err := FrameLen{}(data); err != nil {{", p.name);
                s.push_str("\t\t\ts += `,\"frame\":\"error\"`\n\t\t} else if !ok {\n\t\t\ts += `,\"frame\":null`\n\t\t} else {\n\t\t\ts += fmt.Sprintf(`,\"frame\":%d`, size)\n\t\t}\n");
            }
            s.push_str("\t\tfmt.Println(s + \"}\")\n\t}()\n");
        }
        s.push_str("}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::create_dir_all(dir.join("packets")).unwrap();
        fs::write(dir.join("go.mod"), "module harness\n\ngo 1.21\n").unwrap();
        fs::write(dir.join("packets").join("packets.go"), generated).unwrap();
        fs::write(dir.join("main.go"), harness).unwrap();
        let unformatted = run(Command::new("gofmt").current_dir(dir).args(["-l", "packets"]), "gofmt")?;
        if !unformatted.trim().is_empty() {
            let diff = Command::new("gofmt")
                .current_dir(dir)
                .args(["-d", "packets"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            return Err(format!("generated Go code is not gofmt-clean:\n{}", diff));
        }
        run(Command::new("go").current_dir(dir).args(["vet", "./..."]).env("GOFLAGS", "-mod=mod"), "go vet")?;
        run(
            Command::new("go").current_dir(dir).args(["build", "-o", "harness", "."]).env("GOFLAGS", "-mod=mod"),
            "go build",
        )?;
        run(&mut Command::new(dir.join("harness")), "go harness")
    }
}
