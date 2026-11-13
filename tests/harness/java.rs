use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::generators::java::{class_name, field_name, outer_class, scalar_type};
use packet_builder::ir::{Module, ValueType};
use packet_builder::{GenOptions, Language};
use serde_json::Value;

use super::{Case, Target, packet, quote, resolve_path, run, which};

pub struct JavaTarget;

/// (javac, java): from `$JAVA_HOME/bin`, else PATH. macOS has stubs in
/// /usr/bin that fail without a JDK, so `javac -version` must succeed.
fn toolchain() -> Option<(PathBuf, PathBuf)> {
    let from_home =
        std::env::var_os("JAVA_HOME").map(|h| (Path::new(&h).join("bin/javac"), Path::new(&h).join("bin/java")));
    let (javac, java) = match from_home {
        Some((c, j)) if c.is_file() && j.is_file() => (c, j),
        _ => (which("javac")?, which("java")?),
    };
    let works = Command::new(&javac).arg("-version").output().map(|o| o.status.success()).unwrap_or(false);
    works.then_some((javac, java))
}

/// A Java expression for a `set` value assigned to a member of type `ty`.
fn literal(v: &Value, ty: &ValueType) -> String {
    match v {
        Value::String(s) => quote(s),
        Value::Number(n) => {
            let t = scalar_type(ty);
            if let Some(i) = n.as_i64() {
                format!("({})({}L)", t, i)
            } else if let Some(u) = n.as_u64() {
                format!("({})({}L)", t, u as i64)
            } else {
                format!("({})({:?}d)", t, n.as_f64().unwrap())
            }
        }
        other => panic!("set values must be numbers or strings, got {}", other),
    }
}

impl Target for JavaTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Java)
    }

    fn unavailable(&self) -> Option<String> {
        toolchain().is_none().then(|| "javac/java not found (set JAVA_HOME or PATH)".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let outer = outer_class(&GenOptions::default());
        let mut s = String::from("public final class Main {\n");
        s.push_str("    static final java.io.PrintStream OUT = new java.io.PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, java.nio.charset.StandardCharsets.UTF_8);\n");
        s.push_str("    static byte[] hex(String h) { return java.util.HexFormat.of().parseHex(h); }\n");
        s.push_str(
            "    static String hx(byte[] b) { return \"\\\"\" + java.util.HexFormat.of().formatHex(b) + \"\\\"\"; }\n",
        );
        s.push_str("    static String q(String s) { return \"\\\"\" + s.replace(\"\\\\\", \"\\\\\\\\\").replace(\"\\\"\", \"\\\\\\\"\") + \"\\\"\"; }\n");
        let _ = writeln!(
            s,
            "    static String e({}.PbException e, String pre) {{ return \",\\\"\" + pre + \"error\\\":\" + q(e.getMessage()) + \",\\\"\" + pre + \"kind\\\":\" + q(e.kind().label()) + \",\\\"\" + pre + \"path\\\":\" + q(e.path()); }}\n",
            outer
        );
        s.push_str("    public static void main(String[] args) {\n");
        for i in 0..cases.len() {
            let _ = writeln!(s, "        c{}();", i);
            let _ = writeln!(s, "        s{}();", i);
        }
        s.push_str("        OUT.flush();\n    }\n");
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let class = format!("{}.{}", outer, class_name(&p.name));
            let ver = c.version.map(|v| format!(", {}", v)).unwrap_or_default();
            let _ = writeln!(s, "\n    static void c{}() {{", i);
            let _ = writeln!(s, "        {} p;", class);
            let decode = if c.source {
                let check = match c.unread {
                    Some((from, to)) => format!(
                        "if (Math.max(at, {}L) < Math.min(at + buf.length, {}L)) throw new java.io.IOException(\"fetched an unread byte\"); ",
                        from, to
                    ),
                    None => String::new(),
                };
                format!(
                    "byte[] sd = hex({}); var src = new {}.PbSource(sd.length, {}, (at, buf) -> {{ {}System.arraycopy(sd, (int) at, buf, 0, buf.length); }}); p = {}.decodeFrom(new {}.PbReader(src));",
                    quote(&c.hex),
                    outer,
                    super::SOURCE_PAGE,
                    check,
                    class,
                    outer
                )
            } else {
                format!("p = {}.decode(hex({}){});", class, quote(&c.hex), c.more_args() + &ver)
            };
            let _ = writeln!(
                s,
                "        try {{ {} }} catch ({}.PbException e) {{ OUT.println(\"{{\\\"ok\\\":false\" + e(e, \"\") + \"}}\"); return; }}",
                decode, outer
            );
            for (name, v) in &c.set {
                let path = resolve_path(module, p, name);
                let ty = &path.last().unwrap().1.ty;
                let access: Vec<String> = path.iter().map(|(_, m)| field_name(&m.name)).collect();
                let _ = writeln!(s, "        p.{} = {};", access.join("."), literal(v, ty));
            }
            s.push_str("        String v = p.toJson();\n");
            s.push_str("        byte[] b;\n");
            let _ = writeln!(
                s,
                "        try {{ b = p.encode({}); }} catch ({}.PbException e) {{ OUT.println(\"{{\\\"ok\\\":true,\\\"value\\\":\" + v + e(e, \"encode_\") + \"}}\"); return; }}",
                c.args_then(&ver),
                outer
            );
            s.push_str("        OUT.println(\"{\\\"ok\\\":true,\\\"value\\\":\" + v + \",\\\"encoded\\\":\" + hx(b) + \"}\");\n");
            s.push_str("    }\n");
            let _ = writeln!(s, "\n    static void s{}() {{", i);
            if !c.args.is_empty() {
                s.push_str("        OUT.println(\"{}\");\n    }\n");
                continue;
            }
            let _ = writeln!(s, "        byte[] d = hex({});", quote(&c.hex));
            s.push_str("        String s;\n");
            let _ = writeln!(
                s,
                "        try {{ var st = {}.tryDecode(d{}); s = st.isDone() ? \"{{\\\"try\\\":\\\"done\\\",\\\"n\\\":\" + st.consumed() : \"{{\\\"try\\\":\\\"incomplete\\\",\\\"n\\\":\" + st.needed(); }}",
                class, ver
            );
            let _ = writeln!(s, "        catch ({}.PbException e) {{ s = \"{{\\\"try\\\":\\\"error\\\"\"; }}", outer);
            if super::has_frame(module, p) {
                let _ = writeln!(
                    s,
                    "        try {{ var f = {}.frameLen(d); s += f.isPresent() ? \",\\\"frame\\\":\" + f.getAsInt() : \",\\\"frame\\\":null\"; }}",
                    class
                );
                let _ =
                    writeln!(s, "        catch ({}.PbException e) {{ s += \",\\\"frame\\\":\\\"error\\\"\"; }}", outer);
            }
            s.push_str("        OUT.println(s + \"}\");\n    }\n");
        }
        s.push_str("}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        let (javac, java) = toolchain().unwrap();
        let outer = outer_class(&GenOptions::default());
        let file = format!("{}.java", outer);
        fs::write(dir.join(&file), generated).unwrap();
        fs::write(dir.join("Main.java"), harness).unwrap();
        run(
            Command::new(&javac).current_dir(dir).args([
                "--release",
                "17",
                "-encoding",
                "UTF-8",
                "-Xlint:all,-cast,-options",
                "-Werror",
                "-d",
                "classes",
                &file,
                "Main.java",
            ]),
            "javac",
        )?;
        run(Command::new(&java).current_dir(dir).args(["-cp", "classes", "Main"]), "java harness")
    }
}
