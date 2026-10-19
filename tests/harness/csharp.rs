use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::generators::csharp::{namespace, prop_name};
use packet_builder::ir::{Member, Module, ValueType};
use packet_builder::{GenOptions, Language};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct CSharpTarget;

/// (dotnet executable, csc.dll, reference assembly directory)
fn toolchain() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dotnet = which("dotnet")?;
    let root = fs::canonicalize(&dotnet).ok()?.parent()?.to_path_buf();
    // Highest version directory ("10.0.1" sorts after "8.0.31").
    let newest = |dir: PathBuf| -> Option<PathBuf> {
        let version = |p: &PathBuf| -> Vec<u64> {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            name.split(|c: char| !c.is_ascii_digit()).filter_map(|x| x.parse().ok()).collect()
        };
        let mut entries: Vec<PathBuf> = fs::read_dir(dir).ok()?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort_by_key(version);
        entries.pop()
    };
    let csc = newest(root.join("sdk"))?.join("Roslyn").join("bincore").join("csc.dll");
    let refs = newest(newest(root.join("packs").join("Microsoft.NETCore.App.Ref"))?.join("ref"))?;
    (csc.is_file() && refs.is_dir()).then_some((dotnet, csc, refs))
}

fn value_expr(m: &Member, place: &str) -> String {
    let elem = |v: &str| match &m.ty {
        ValueType::Int { .. } => format!("{}.ToString(CultureInfo.InvariantCulture)", v),
        ValueType::Float { .. } => format!("((double){}).ToString(\"R\", CultureInfo.InvariantCulture)", v),
        ValueType::Mac => format!("Hx({})", v),
        ValueType::Packet(n) => format!("Dump{}({})", n, v),
        ValueType::Str => format!("System.Text.Json.JsonSerializer.Serialize({})", v),
    };
    match &m.array {
        None => elem(place),
        Some(_) if m.ty.is_byte() => format!("Hx({})", place),
        Some(_) => format!("\"[\" + string.Join(\",\", {}.Select(x => {})) + \"]\"", place, elem("x")),
    }
}

impl Target for CSharpTarget {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn unavailable(&self) -> Option<String> {
        toolchain().is_none().then(|| "dotnet SDK (csc.dll and reference assemblies) not found".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from("using System;\nusing System.Globalization;\nusing System.Linq;\n");
        let _ = writeln!(s, "using {};\n", namespace(&GenOptions::default()));
        s.push_str("static class Harness\n{\n");
        s.push_str(
            "    static string Hx(byte[] b) => \"\\\"\" + Convert.ToHexString(b).ToLowerInvariant() + \"\\\"\";\n",
        );
        s.push_str("    static string Q(string s) => \"\\\"\" + s.Replace(\"\\\\\", \"\\\\\\\\\").Replace(\"\\\"\", \"\\\\\\\"\") + \"\\\"\";\n\n");
        for p in &module.packets {
            let _ = writeln!(
                s,
                "    static string Dump{}({} p)\n    {{\n        var parts = new System.Collections.Generic.List<string>();",
                p.name, p.name
            );
            for m in &p.members {
                let place = format!("p.{}", prop_name(&p.name, &m.name));
                let _ = writeln!(s, "        parts.Add(\"\\\"{}\\\":\" + {});", m.name, value_expr(m, &place));
            }
            s.push_str("        return \"{\" + string.Join(\",\", parts) + \"}\";\n    }\n\n");
        }
        s.push_str("    static void Main()\n    {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            s.push_str("        {\n");
            let _ = writeln!(s, "            {} p;", p.name);
            let _ =
                writeln!(s, "            try {{ p = {}.Decode(Convert.FromHexString({})); }}", p.name, quote(&c.hex));
            s.push_str("            catch (PbException e) { Console.WriteLine(\"{\\\"ok\\\":false,\\\"error\\\":\" + Q(e.Message) + \"}\"); goto done; }\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "            p.{} = {};",
                    super::accessor(module, p, name, |o, m| prop_name(&o.name, &m.name)),
                    set_literal(v)
                );
            }
            let _ = writeln!(s, "            var v = Dump{}(p);", p.name);
            s.push_str("            byte[] b;\n");
            s.push_str("            try { b = p.Encode(); }\n");
            s.push_str("            catch (PbException e) { Console.WriteLine(\"{\\\"ok\\\":true,\\\"value\\\":\" + v + \",\\\"encode_error\\\":\" + Q(e.Message) + \"}\"); goto done; }\n");
            s.push_str("            Console.WriteLine(\"{\\\"ok\\\":true,\\\"value\\\":\" + v + \",\\\"encoded\\\":\" + Hx(b) + \"}\");\n");
            s.push_str("            done:;\n        }\n");
        }
        s.push_str("    }\n}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        let (dotnet, csc, refs) = toolchain().unwrap();
        fs::write(dir.join("Packets.cs"), generated).unwrap();
        fs::write(dir.join("Main.cs"), harness).unwrap();
        fs::write(
            dir.join("harness.runtimeconfig.json"),
            r#"{"runtimeOptions":{"tfm":"net8.0","rollForward":"LatestMajor","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"}}}"#,
        )
        .unwrap();
        let mut cmd = Command::new(&dotnet);
        cmd.current_dir(dir).arg(&csc).args(["-nologo", "-warnaserror+", "-nowarn:CS0164", "-out:harness.dll"]);
        for r in fs::read_dir(&refs).unwrap() {
            let r = r.unwrap().path();
            if r.extension().map(|e| e == "dll").unwrap_or(false) {
                cmd.arg(format!("-r:{}", r.display()));
            }
        }
        cmd.args(["Packets.cs", "Main.cs"]);
        run(&mut cmd, "csc")?;
        run(Command::new(&dotnet).current_dir(dir).arg("harness.dll"), "c# harness")
    }
}
