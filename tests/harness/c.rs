use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::c_generator::{ident, len_ident};
use packet_builder::ir::{Member, Module, Packet, ValueType};

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct CTarget;

fn compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| which(c).is_some())
}

/// Statements printing one member value.
fn dump_member(s: &mut String, p: &Packet, m: &Member) {
    let place = format!("p->{}", ident(&m.name));
    let elem = |v: &str| match &m.ty {
        ValueType::Int { signed: true, .. } => format!("printf(\"%lld\", (long long){});", v),
        ValueType::Int { .. } => format!("printf(\"%llu\", (unsigned long long){});", v),
        ValueType::Float { .. } => format!("printf(\"%.17g\", (double){});", v),
        ValueType::Mac => format!("hx({}, 6);", v),
        ValueType::Packet(n) => format!("dump_{}(&{});", n, v),
    };
    match &m.array {
        None => {
            let _ = writeln!(s, "    {}", elem(&place));
        }
        Some(_) => {
            let len = format!("p->{}", len_ident(p, m));
            if m.ty.is_byte() {
                let _ = writeln!(s, "    hx({}, {});", place, len);
            } else {
                let _ = writeln!(
                    s,
                    "    printf(\"[\"); for (size_t i = 0; i < {}; i++) {{ if (i) printf(\",\"); {} }} printf(\"]\");",
                    len,
                    elem(&format!("{}[i]", place))
                );
            }
        }
    }
}

impl Target for CTarget {
    fn language(&self) -> Language {
        Language::C
    }

    fn unavailable(&self) -> Option<String> {
        compiler().is_none().then(|| "no C compiler (cc, gcc, clang) on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from(
            "#define PACKETS_IMPLEMENTATION\n#include \"packets.h\"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n",
        );
        s.push_str("static void hx(const uint8_t *b, size_t n) { printf(\"\\\"\"); for (size_t i = 0; i < n; i++) printf(\"%02x\", b[i]); printf(\"\\\"\"); }\n");
        s.push_str("static size_t unhex(const char *h, uint8_t *out) { size_t n = strlen(h) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, \"%2x\", &v); out[i] = (uint8_t)v; } return n; }\n\n");
        for p in &module.packets {
            let _ = writeln!(s, "static void dump_{}(const {} *p);", p.name, p.name);
        }
        for p in &module.packets {
            let _ = writeln!(s, "static void dump_{}(const {} *p) {{", p.name, p.name);
            s.push_str("    printf(\"{\");\n");
            if p.members.is_empty() {
                s.push_str("    (void)p;\n");
            }
            for (i, m) in p.members.iter().enumerate() {
                let _ = writeln!(s, "    printf(\"{}\\\"{}\\\":\");", if i > 0 { "," } else { "" }, m.name);
                dump_member(&mut s, p, m);
            }
            s.push_str("    printf(\"}\");\n}\n\n");
        }
        s.push_str("int main(void) {\n    static uint8_t data[65536];\n");
        for c in cases {
            let p = packet(module, &c.packet);
            s.push_str("    {\n");
            let _ = writeln!(s, "        size_t n = unhex({}, data);", quote(&c.hex));
            let _ = writeln!(s, "        {} p;", p.name);
            s.push_str("        uint8_t *out = NULL; size_t out_len = 0; int rc;\n");
            // Copy into an exact-size heap buffer so ASan catches over-reads.
            s.push_str("        uint8_t *in = malloc(n ? n : 1); memcpy(in, data, n);\n");
            let _ = writeln!(s, "        rc = {}_decode(&p, in, n);", p.name);
            s.push_str("        free(in);\n");
            s.push_str("        if (rc != PB_OK) { printf(\"{\\\"ok\\\":false,\\\"error\\\":\\\"%s\\\"}\\n\", pb_strerror(rc)); }\n");
            s.push_str("        else {\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "            p.{} = {};",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    set_literal(v)
                );
            }
            s.push_str("            printf(\"{\\\"ok\\\":true,\\\"value\\\":\");\n");
            let _ = writeln!(s, "            dump_{}(&p);", p.name);
            let _ = writeln!(s, "            rc = {}_encode(&p, &out, &out_len);", p.name);
            s.push_str(
                "            if (rc != PB_OK) printf(\",\\\"encode_error\\\":\\\"%s\\\"}\\n\", pb_strerror(rc));\n",
            );
            s.push_str(
                "            else { printf(\",\\\"encoded\\\":\"); hx(out, out_len); printf(\"}\\n\"); free(out); }\n",
            );
            let _ = writeln!(s, "            {}_free(&p);", p.name);
            s.push_str("        }\n    }\n");
        }
        s.push_str("    return 0;\n}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.h"), generated).unwrap();
        fs::write(dir.join("main.c"), harness).unwrap();
        let cc = compiler().unwrap();
        // The header must also compile on its own as strict C99.
        fs::write(dir.join("lib.c"), "#define PACKETS_IMPLEMENTATION\n#include \"packets.h\"\n").unwrap();
        run(
            Command::new(cc).current_dir(dir).args([
                "-std=c99",
                "-pedantic",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                "lib.c",
                "-o",
                "lib.o",
            ]),
            "cc (strict C99)",
        )?;
        let sanitize = std::env::var("PB_C_NO_SANITIZE").is_err();
        let mut cmd = Command::new(cc);
        cmd.current_dir(dir).args(["-std=c11", "-g", "-Wall", "-Wextra", "-Werror", "main.c", "-o", "harness", "-lm"]);
        if sanitize {
            cmd.args(["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]);
        }
        run(&mut cmd, "cc")?;
        run(&mut Command::new(dir.join("harness")), "c harness")
    }
}
