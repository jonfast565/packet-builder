use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::generators::csharp::{namespace, prop_name};
use packet_builder::ir::Module;
use packet_builder::{GenOptions, Language};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct CSharpTarget;

/// (dotnet executable, csc.dll, reference assembly directory)
fn toolchain() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dotnet = which("dotnet")?;
    // `dotnet --list-sdks` prints "10.0.401 [/root/sdk]"; Homebrew keeps the
    // root under libexec rather than next to the `dotnet` binary.
    let listed = Command::new(&dotnet).arg("--list-sdks").output().ok().and_then(|o| {
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        let line = text.lines().last()?.to_string();
        let path = line.split_once('[')?.1.trim_end_matches(']');
        Some(PathBuf::from(path).parent()?.to_path_buf())
    });
    let root = match listed {
        Some(root) => root,
        None => fs::canonicalize(&dotnet).ok()?.parent()?.to_path_buf(),
    };
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

impl Target for CSharpTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::CSharp)
    }

    fn unavailable(&self) -> Option<String> {
        toolchain().is_none().then(|| "dotnet SDK (csc.dll and reference assemblies) not found".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("using System;\nusing System.Globalization;\nusing System.Linq;\n");
        let _ = writeln!(s, "using {};\n", namespace(&GenOptions::default()));
        s.push_str("static class Harness\n{\n");
        s.push_str(
            "    static string Hx(byte[] b) => \"\\\"\" + Convert.ToHexString(b).ToLowerInvariant() + \"\\\"\";\n",
        );
        s.push_str("    static string Q(string s) => \"\\\"\" + s.Replace(\"\\\\\", \"\\\\\\\\\").Replace(\"\\\"\", \"\\\\\\\"\") + \"\\\"\";\n");
        s.push_str("    static string E(PbException e, string pre) => \",\\\"\" + pre + \"error\\\":\" + Q(e.Message) + \",\\\"\" + pre + \"kind\\\":\" + Q(e.Kind.ToString().ToLowerInvariant()) + \",\\\"\" + pre + \"path\\\":\" + Q(e.Path);\n\n");
        s.push_str("    static void Main()\n    {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            s.push_str("        {\n");
            let _ = writeln!(s, "            {} p;", p.name);
            let ver = c.version.map(|v| format!(", version: {}", v)).unwrap_or_default();
            let _ = writeln!(
                s,
                "            try {{ p = {}.Decode(Convert.FromHexString({}){}); }}",
                p.name,
                quote(&c.hex),
                ver
            );
            s.push_str("            catch (PbException e) { Console.WriteLine(\"{\\\"ok\\\":false\" + E(e, \"\") + \"}\"); goto done; }\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "            p.{} = {};",
                    super::accessor(module, p, name, |o, m| prop_name(&o.name, &m.name)),
                    set_literal(v)
                );
            }
            s.push_str("            var v = p.ToJson();\n");
            s.push_str("            byte[] b;\n");
            let _ = writeln!(s, "            try {{ b = p.Encode({}); }}", ver.trim_start_matches(", "));
            s.push_str("            catch (PbException e) { Console.WriteLine(\"{\\\"ok\\\":true,\\\"value\\\":\" + v + E(e, \"encode_\") + \"}\"); goto done; }\n");
            s.push_str("            Console.WriteLine(\"{\\\"ok\\\":true,\\\"value\\\":\" + v + \",\\\"encoded\\\":\" + Hx(b) + \"}\");\n");
            s.push_str("            done:;\n        }\n");
            s.push_str("        {\n");
            let _ = writeln!(s, "            var d = Convert.FromHexString({});", quote(&c.hex));
            s.push_str("            string s;\n");
            let _ = writeln!(
                s,
                "            try {{ var st = {}.TryDecode(d{}); s = st.IsDone ? \"{{\\\"try\\\":\\\"done\\\",\\\"n\\\":\" + st.Consumed : \"{{\\\"try\\\":\\\"incomplete\\\",\\\"n\\\":\" + st.Needed; }}",
                p.name, ver
            );
            s.push_str("            catch (PbException) { s = \"{\\\"try\\\":\\\"error\\\"\"; }\n");
            if super::has_frame(module, p) {
                let _ = writeln!(
                    s,
                    "            try {{ var f = {}.FrameLen(d); s += f == null ? \",\\\"frame\\\":null\" : \",\\\"frame\\\":\" + f; }}",
                    p.name
                );
                s.push_str("            catch (PbException) { s += \",\\\"frame\\\":\\\"error\\\"\"; }\n");
            }
            s.push_str("            Console.WriteLine(s + \"}\");\n        }\n");
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
