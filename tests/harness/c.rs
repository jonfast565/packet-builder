use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::c::{ident, len_ident};
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
        ValueType::Str => format!("js({}, p->{});", v, len_ident(p, m)),
        ValueType::Union(n) => format!("dump_{}(&{});", n, v),
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
    fn language(&self) -> Option<Language> {
        Some(Language::C)
    }

    fn unavailable(&self) -> Option<String> {
        compiler().is_none().then(|| "no C compiler (cc, gcc, clang) on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case]) -> String {
        let mut s = String::from(
            "#define PACKETS_IMPLEMENTATION\n#include \"packets.h\"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n",
        );
        s.push_str("__attribute__((unused)) static char *dupstr(const char *s) { size_t n = strlen(s); char *d = malloc(n + 1); memcpy(d, s, n + 1); return d; }\n");
        s.push_str("static void js(const char *s, size_t n) { putchar('\"'); for (size_t i = 0; i < n; i++) { unsigned char c = (unsigned char)s[i]; if (c == '\"' || c == '\\\\') printf(\"\\\\%c\", c); else if (c < 0x20) printf(\"\\\\u%04x\", c); else putchar(c); } putchar('\"'); }\n");
        s.push_str("static void hx(const uint8_t *b, size_t n) { printf(\"\\\"\"); for (size_t i = 0; i < n; i++) printf(\"%02x\", b[i]); printf(\"\\\"\"); }\n");
        s.push_str("static const char *kindname(int rc) { switch (rc) { case PB_ERR_INCOMPLETE: return \"incomplete\"; case PB_ERR_INVALID: return \"invalid\"; case PB_ERR_RANGE: return \"range\"; case PB_ERR_TEXT: return \"text\"; case PB_ERR_MISMATCH: return \"mismatch\"; case PB_ERR_CONSTRAINT: return \"constraint\"; default: return \"other\"; } }\n");
        s.push_str("static void err(const char *pre, int rc, const char *desc, const char *path) { printf(\"\\\"%serror\\\":\", pre); js(desc, strlen(desc)); printf(\",\\\"%skind\\\":\\\"%s\\\",\\\"%spath\\\":\", pre, kindname(rc), pre); js(path, strlen(path)); }\n");
        s.push_str("static size_t unhex(const char *h, uint8_t *out) { size_t n = strlen(h) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, \"%2x\", &v); out[i] = (uint8_t)v; } return n; }\n\n");
        for p in &module.packets {
            let _ = writeln!(s, "static void dump_{}(const {} *p);", p.name, p.name);
        }
        for u in &module.unions {
            let _ = writeln!(s, "static void dump_{}(const {} *v) {{\n    switch (v->kind) {{", u.name, u.name);
            for arm in &u.arms {
                let id = ident(&arm.name);
                let head = format!("printf(\"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\");", arm.name);
                let value = match (&arm.ty, arm.is_bytes()) {
                    (None, _) => "printf(\"null\");".to_string(),
                    (Some(_), true) => format!("hx(v->u.{}.data, v->u.{}.len);", id, id),
                    (Some(ValueType::Packet(n)), _) => format!("dump_{}(&v->u.{});", n, id),
                    (Some(t), _) if t.is_signed() => format!("printf(\"%lld\", (long long)v->u.{});", id),
                    (Some(_), _) => format!("printf(\"%llu\", (unsigned long long)v->u.{});", id),
                };
                let _ = writeln!(
                    s,
                    "    case {}: {} {} printf(\"}}\"); break;",
                    packet_builder::generators::c::arm_kind(&u.name, arm),
                    head,
                    value
                );
            }
            s.push_str("    default: printf(\"null\"); break;\n    }\n}\n\n");
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
            s.push_str("        int rc; pb_reader r; pb_writer w; char desc[512], path[256];\n");
            // Copy into an exact-size heap buffer so ASan catches over-reads.
            s.push_str("        uint8_t *in = malloc(n ? n : 1); memcpy(in, data, n);\n");
            s.push_str("        pb_reader_init(&r, in, n);\n");
            let _ = writeln!(s, "        rc = {}_decode_from(&p, &r);", p.name);
            s.push_str("        free(in);\n");
            s.push_str("        if (rc != PB_OK) { printf(\"{\\\"ok\\\":false,\"); err(\"\", rc, pb_reader_describe(&r, desc, sizeof desc), pb_reader_path(&r, path, sizeof path)); printf(\"}\\n\"); }\n");
            s.push_str("        else {\n");
            for (name, v) in &c.set {
                let path = super::accessor(module, p, name, |_, m| ident(&m.name));
                if v.is_string() {
                    let len = super::accessor(module, p, name, |o, m| {
                        if m.name == name.rsplit('.').next().unwrap() { len_ident(o, m) } else { ident(&m.name) }
                    });
                    let _ = writeln!(
                        s,
                        "            free(p.{}); p.{} = dupstr({}); p.{} = strlen(p.{});",
                        path,
                        path,
                        set_literal(v),
                        len,
                        path
                    );
                } else {
                    let _ = writeln!(s, "            p.{} = {};", path, set_literal(v));
                }
            }
            s.push_str("            printf(\"{\\\"ok\\\":true,\\\"value\\\":\");\n");
            let _ = writeln!(s, "            dump_{}(&p);", p.name);
            s.push_str("            pb_writer_init(&w);\n");
            let _ = writeln!(s, "            rc = {}_encode_to(&p, &w);", p.name);
            s.push_str(
                "            if (rc != PB_OK) { printf(\",\"); err(\"encode_\", rc, pb_writer_describe(&w, desc, sizeof desc), pb_writer_path(&w, path, sizeof path)); printf(\"}\\n\"); }\n",
            );
            s.push_str("            else { printf(\",\\\"encoded\\\":\"); hx(w.buf, w.len); printf(\"}\\n\"); }\n");
            s.push_str("            pb_writer_free(&w);\n");
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
