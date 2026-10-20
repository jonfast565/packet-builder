use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::c::{ident, len_ident};
use packet_builder::ir::Module;

use super::{Case, Target, packet, quote, run, set_literal, which};

pub struct CTarget;

fn compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| which(c).is_some())
}

impl Target for CTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::C)
    }

    fn unavailable(&self) -> Option<String> {
        compiler().is_none().then(|| "no C compiler (cc, gcc, clang) on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from(
            "#define PACKETS_IMPLEMENTATION\n#include \"packets.h\"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n",
        );
        s.push_str("__attribute__((unused)) static char *dupstr(const char *s) { size_t n = strlen(s); char *d = malloc(n + 1); memcpy(d, s, n + 1); return d; }\n");
        s.push_str("static void js(const char *s, size_t n) { putchar('\"'); for (size_t i = 0; i < n; i++) { unsigned char c = (unsigned char)s[i]; if (c == '\"' || c == '\\\\') printf(\"\\\\%c\", c); else if (c < 0x20) printf(\"\\\\u%04x\", c); else putchar(c); } putchar('\"'); }\n");
        s.push_str("static void hx(const uint8_t *b, size_t n) { printf(\"\\\"\"); for (size_t i = 0; i < n; i++) printf(\"%02x\", b[i]); printf(\"\\\"\"); }\n");
        s.push_str("static const char *kindname(int rc) { switch (rc) { case PB_ERR_INCOMPLETE: return \"incomplete\"; case PB_ERR_INVALID: return \"invalid\"; case PB_ERR_RANGE: return \"range\"; case PB_ERR_TEXT: return \"text\"; case PB_ERR_MISMATCH: return \"mismatch\"; case PB_ERR_CONSTRAINT: return \"constraint\"; default: return \"other\"; } }\n");
        s.push_str("static void err(const char *pre, int rc, const char *desc, const char *path) { printf(\"\\\"%serror\\\":\", pre); js(desc, strlen(desc)); printf(\",\\\"%skind\\\":\\\"%s\\\",\\\"%spath\\\":\", pre, kindname(rc), pre); js(path, strlen(path)); }\n");
        s.push_str("static size_t unhex(const char *h, uint8_t *out) { size_t n = strlen(h) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, \"%2x\", &v); out[i] = (uint8_t)v; } return n; }\n\n");
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
            let _ = writeln!(s, "            {{ char *j = {}_to_json(&p); printf(\"%s\", j); free(j); }}", p.name);
            s.push_str("            pb_writer_init(&w);\n");
            let _ = writeln!(s, "            rc = {}_encode_to(&p, &w);", p.name);
            s.push_str("            if (rc == PB_OK) rc = pb_writer_finish(&w);\n");
            s.push_str(
                "            if (rc != PB_OK) { printf(\",\"); err(\"encode_\", rc, pb_writer_describe(&w, desc, sizeof desc), pb_writer_path(&w, path, sizeof path)); printf(\"}\\n\"); }\n",
            );
            s.push_str("            else { printf(\",\\\"encoded\\\":\"); hx(w.buf, w.len); printf(\"}\\n\"); }\n");
            s.push_str("            pb_writer_free(&w);\n");
            let _ = writeln!(s, "            {}_free(&p);", p.name);
            // Last: zero-copy values point into the input.
            s.push_str("        }\n        free(in);\n    }\n");
            s.push_str("    {\n");
            let _ = writeln!(s, "        size_t n = unhex({}, data), used = 0, size = 0;", quote(&c.hex));
            let _ = writeln!(s, "        {} p;", p.name);
            s.push_str("        int rc;\n        uint8_t *in = malloc(n ? n : 1); memcpy(in, data, n);\n");
            let _ = writeln!(s, "        rc = {}_try_decode(&p, in, n, &used);", p.name);
            let _ = writeln!(
                s,
                "        if (rc == PB_OK) {{ printf(\"{{\\\"try\\\":\\\"done\\\",\\\"n\\\":%zu\", used); {}_free(&p); }}",
                p.name
            );
            s.push_str("        else if (rc == PB_ERR_INCOMPLETE) printf(\"{\\\"try\\\":\\\"incomplete\\\",\\\"n\\\":%zu\", used);\n");
            s.push_str("        else printf(\"{\\\"try\\\":\\\"error\\\"\");\n");
            if super::has_frame(module, p) {
                let _ = writeln!(s, "        rc = {}_frame_len(in, n, &size);", p.name);
                s.push_str("        if (rc == PB_OK) printf(\",\\\"frame\\\":%zu\", size);\n");
                s.push_str("        else if (rc == PB_ERR_INCOMPLETE) printf(\",\\\"frame\\\":null\");\n");
                s.push_str("        else printf(\",\\\"frame\\\":\\\"error\\\"\");\n");
            }
            s.push_str("        (void)size;\n        free(in);\n        printf(\"}\\n\");\n    }\n");
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
