use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::common::union::variant_name;
use packet_builder::generators::go::field_name;
use packet_builder::ir::{Member, Module, ValueType};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct GoTarget;

fn value_expr(m: &Member, place: &str) -> String {
    let elem = |v: &str| match &m.ty {
        ValueType::Int { signed: true, .. } => format!("strconv.FormatInt(int64({}), 10)", v),
        ValueType::Int { .. } => format!("strconv.FormatUint(uint64({}), 10)", v),
        ValueType::Float { .. } => format!("strconv.FormatFloat(float64({}), 'g', -1, 64)", v),
        ValueType::Mac => format!("hx({}[:])", v),
        ValueType::Packet(n) => format!("dump{}(&{})", n, v),
        ValueType::Str => format!("js({})", v),
        ValueType::Union(n) => format!("dump{}(&{})", n, v),
    };
    match &m.array {
        None => elem(place),
        Some(_) if m.ty.is_byte() => format!("hx({})", place),
        Some(_) => format!(
            "func() string {{ parts := []string{{}}; for i := range {} {{ parts = append(parts, {}) }}; return \"[\" + strings.Join(parts, \",\") + \"]\" }}()",
            place,
            elem(&format!("{}[i]", place))
        ),
    }
}

impl Target for GoTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Go)
    }

    fn unavailable(&self) -> Option<String> {
        which("go").is_none().then(|| "go not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from(
            "package main\n\nimport (\n\t\"encoding/hex\"\n\t\"encoding/json\"\n\t\"fmt\"\n\t\"strconv\"\n\t\"strings\"\n\n\t. \"harness/packets\"\n)\n\n",
        );
        s.push_str("var _ = strings.Join\n\n");
        s.push_str("func js(v string) string { b, _ := json.Marshal(v); return string(b) }\n\n");
        s.push_str("func pbE(err error, pre string) string {\n\te := err.(*PbError)\n\treturn fmt.Sprintf(\"\\\"%serror\\\":%s,\\\"%skind\\\":%s,\\\"%spath\\\":%s\", pre, strconv.Quote(e.Error()), pre, js(e.Kind.String()), pre, js(e.Path))\n}\n\n");
        s.push_str("func hx(b []byte) string { return \"\\\"\" + hex.EncodeToString(b) + \"\\\"\" }\n\n");
        for u in &module.unions {
            let _ = writeln!(s, "func dump{}(v *{}) string {{\n\tswitch v.Kind {{", u.name, u.name);
            for arm in &u.arms {
                let field = format!("v.{}", variant_name(arm));
                let value = match (&arm.ty, arm.is_bytes()) {
                    (None, _) => "\"null\"".to_string(),
                    (Some(_), true) => format!("hx({})", field),
                    (Some(ValueType::Packet(n)), _) => format!("dump{}({})", n, field),
                    (Some(t), _) if t.is_signed() => format!("strconv.FormatInt(int64({}), 10)", field),
                    (Some(_), _) => format!("strconv.FormatUint(uint64({}), 10)", field),
                };
                let _ = writeln!(
                    s,
                    "\tcase {}{}:\n\t\treturn \"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\" + {} + \"}}\"",
                    u.name,
                    variant_name(arm),
                    arm.name,
                    value
                );
            }
            s.push_str("\t}\n\treturn \"null\"\n}\n\n");
        }
        for p in &module.packets {
            let _ = writeln!(s, "func dump{}(p *{}) string {{", p.name, p.name);
            s.push_str("\tparts := []string{}\n");
            for m in &p.members {
                let place = format!("p.{}", field_name(&m.name));
                let _ = writeln!(s, "\tparts = append(parts, \"\\\"{}\\\":\"+{})", m.name, value_expr(m, &place));
            }
            s.push_str("\treturn \"{\" + strings.Join(parts, \",\") + \"}\"\n}\n\n");
        }
        s.push_str("func main() {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            s.push_str("\tfunc() {\n");
            let _ = writeln!(s, "\t\tdata, _ := hex.DecodeString({})", quote(&c.hex));
            let _ = writeln!(s, "\t\tp, err := Decode{}(data)", p.name);
            s.push_str("\t\tif err != nil {\n\t\t\tfmt.Printf(\"{\\\"ok\\\":false,%s}\\n\", pbE(err, \"\"))\n\t\t\treturn\n\t\t}\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "\t\tp.{} = {}",
                    super::accessor(module, p, name, |_, m| field_name(&m.name)),
                    set_literal(v)
                );
            }
            let _ = writeln!(s, "\t\tv := dump{}(p)", p.name);
            s.push_str("\t\tb, err := p.Encode()\n");
            s.push_str("\t\tif err != nil {\n\t\t\tfmt.Printf(\"{\\\"ok\\\":true,\\\"value\\\":%s,%s}\\n\", v, pbE(err, \"encode_\"))\n\t\t\treturn\n\t\t}\n");
            s.push_str("\t\tfmt.Printf(\"{\\\"ok\\\":true,\\\"value\\\":%s,\\\"encoded\\\":%s}\\n\", v, hx(b))\n");
            s.push_str("\t}()\n");
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
