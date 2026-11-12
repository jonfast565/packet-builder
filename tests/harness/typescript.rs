use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::typescript::{ident, is_big, type_name};
use packet_builder::ir::Module;
use serde_json::Value;

use super::{Case, Target, packet, quote, resolve_path, run, set_literal, which};

pub struct TypeScriptTarget;

impl Target for TypeScriptTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::TypeScript)
    }

    fn unavailable(&self) -> Option<String> {
        which("node").is_none().then(|| "node not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("import * as pb from \"./packets.ts\";\n\n");
        s.push_str(
            "function pbE(e: unknown, pre: string): string {\n  if (!(e instanceof pb.PbError)) throw e;\n  \
             return `,\"${pre}error\":${JSON.stringify(e.message)},\"${pre}kind\":${JSON.stringify(e.kind)},\
             \"${pre}path\":${JSON.stringify(e.path)}`;\n}\n\n",
        );
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let class = format!("pb.{}", type_name(&p.name));
            let ver = c.version.map(|v| format!(", {}", v)).unwrap_or_default();
            let _ = writeln!(s, "function case{}(): void {{", i);
            let _ = writeln!(s, "  let p: {};", class);
            let _ = writeln!(s, "  try {{\n    p = {}.decode(pb.pbFromHex({}){});", class, quote(&c.hex), ver);
            s.push_str("  } catch (e) {\n    console.log('{\"ok\":false' + pbE(e, \"\") + \"}\");\n    return;\n  }\n");
            for (name, v) in &c.set {
                let path = resolve_path(module, p, name);
                let target = path.iter().map(|(_, m)| ident(&m.name)).collect::<Vec<_>>().join(".");
                let big = path.last().is_some_and(|(_, m)| is_big(&m.ty));
                let lit = match v {
                    Value::Number(_) if big => format!("{}n", set_literal(v)),
                    _ => set_literal(v),
                };
                let _ = writeln!(s, "  p.{} = {};", target, lit);
            }
            s.push_str("  const v = p.toJson();\n  let b: Uint8Array;\n");
            let _ = writeln!(s, "  try {{\n    b = p.encode({});", ver.trim_start_matches(", "));
            s.push_str(
                "  } catch (e) {\n    console.log('{\"ok\":true,\"value\":' + v + pbE(e, \"encode_\") + \"}\");\n    \
                 return;\n  }\n",
            );
            s.push_str(
                "  console.log('{\"ok\":true,\"value\":' + v + ',\"encoded\":\"' + pb.pbToHex(b) + '\"}');\n}\n\n",
            );
            let _ = writeln!(s, "function stream{}(): void {{", i);
            let _ = writeln!(s, "  const d = pb.pbFromHex({});", quote(&c.hex));
            s.push_str("  let s: string;\n  try {\n");
            let _ = writeln!(s, "    const [p, n] = {}.tryDecode(d{});", class, ver);
            s.push_str("    s = `{\"try\":\"${p !== null ? \"done\" : \"incomplete\"}\",\"n\":${n}`;\n");
            s.push_str(
                "  } catch (e) {\n    if (!(e instanceof pb.PbError)) throw e;\n    s = '{\"try\":\"error\"';\n  }\n",
            );
            if super::has_frame(module, p) {
                s.push_str("  try {\n");
                let _ = writeln!(s, "    const f = {}.frameLen(d);", class);
                s.push_str("    s += ',\"frame\":' + (f === null ? \"null\" : String(f));\n");
                s.push_str(
                    "  } catch (e) {\n    if (!(e instanceof pb.PbError)) throw e;\n    s += ',\"frame\":\"error\"';\n  }\n",
                );
            }
            s.push_str("  console.log(s + \"}\");\n}\n\n");
        }
        for i in 0..cases.len() {
            let _ = writeln!(s, "case{}();\nstream{}();", i, i);
        }
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.ts"), generated).unwrap();
        fs::write(dir.join("main.ts"), harness).unwrap();
        fs::write(dir.join("package.json"), "{\"type\":\"module\"}\n").unwrap();
        // Type-check too, when Deno is there (Node only strips the types).
        if which("deno").is_some() {
            fs::write(dir.join("deno.json"), "{\"compilerOptions\":{\"strict\":true}}\n").unwrap();
            run(Command::new("deno").current_dir(dir).args(["check", "--quiet", "main.ts"]), "deno check")?;
        }
        run(Command::new("node").current_dir(dir).arg("main.ts"), "node harness")
    }
}
