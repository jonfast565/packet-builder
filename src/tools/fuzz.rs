//! `packet_builder fuzz`: fuzzing harnesses that check that whatever a
//! packet decodes from and encodes (a `lenient` field may hold a value its
//! encoder rejects) decodes again and encodes to the same bytes. Rust gets a
//! cargo-fuzz project; C gets libFuzzer harnesses that also build without
//! libFuzzer (`-DPB_FUZZ_MAIN`) to run saved inputs.

use std::fmt::Write as _;

use crate::generators::common::GenOptions;
use crate::ir::Module;
use crate::{Language, generate_module};

/// Packets that can be decoded on their own (no parameters).
fn targets(module: &Module) -> Vec<&str> {
    module.packets.iter().filter(|p| p.params.is_empty()).map(|p| p.name.as_str()).collect()
}

/// `src/roundtrip.rs`: one `roundtrip_<Packet>(data)` per packet.
pub fn rust_roundtrip(module: &Module) -> String {
    let mut s = String::from(
        "//! Round trips: a value decoded from any bytes, once encoded, must decode\n\
         //! again and encode to the same bytes. Called by the fuzz targets.\n\n\
         #![allow(non_snake_case)]\n\nuse crate::packets::*;\n",
    );
    for name in targets(module) {
        let _ = write!(
            s,
            "\n/// Decode `data` as a {n}; if it decodes and encodes, the encoding must round-trip.\n\
             pub fn roundtrip_{n}(data: &[u8]) {{\n    \
             let Ok(p) = {n}::decode(data) else {{ return }};\n    \
             let Ok(bytes) = p.encode() else {{ return }};\n    \
             let q = {n}::decode(&bytes).expect(\"an encoded {n} decodes\");\n    \
             assert_eq!(q.encode().expect(\"a {n} encodes again\"), bytes, \"encoding a {n} is stable\");\n}}\n",
            n = name
        );
    }
    s
}

/// The files of a cargo-fuzz project for `module`: (path, contents).
pub fn rust_project(module: &Module, package: &str) -> Vec<(String, String)> {
    let krate = format!("{}_fuzz", package);
    let mut toml = format!(
        "[package]\nname = \"{}\"\nversion = \"0.0.0\"\npublish = false\nedition = \"2024\"\n\n\
         [package.metadata]\ncargo-fuzz = true\n\n[dependencies]\nlibfuzzer-sys = \"0.4\"\n\n\
         [lib]\npath = \"src/lib.rs\"\n",
        krate
    );
    let mut files = Vec::new();
    for name in targets(module) {
        let target = name.to_ascii_lowercase();
        let _ = write!(
            toml,
            "\n[[bin]]\nname = \"{}\"\npath = \"fuzz_targets/{}.rs\"\ntest = false\ndoc = false\nbench = false\n",
            target, target
        );
        files.push((
            format!("fuzz_targets/{}.rs", target),
            format!(
                "#![no_main]\n\nuse libfuzzer_sys::fuzz_target;\n\nfuzz_target!(|data: &[u8]| {}::roundtrip::roundtrip_{}(data));\n",
                krate, name
            ),
        ));
    }
    toml.push_str("\n[workspace]\n");
    let opts = GenOptions { package: package.to_string(), ..GenOptions::default() };
    files.push(("Cargo.toml".into(), toml));
    files.push(("src/lib.rs".into(), "pub mod packets;\npub mod roundtrip;\n".into()));
    files.push(("src/packets.rs".into(), generate_module(module, Language::Rust, &opts)));
    files.push(("src/roundtrip.rs".into(), rust_roundtrip(module)));
    let first = targets(module).first().map(|n| n.to_ascii_lowercase()).unwrap_or_default();
    files.push((
        "README.md".into(),
        format!(
            "# Fuzzing {pkg}\n\nWith cargo-fuzz (nightly Rust):\n\n```sh\ncargo +nightly fuzz run --fuzz-dir . {first}\n```\n\n\
             Each target decodes the input as one packet; whatever decodes and encodes\n\
             must decode again and encode to the same bytes (`src/roundtrip.rs`).\n",
            pkg = package,
            first = first
        ),
    ));
    files
}

/// The files of the C libFuzzer harnesses: the header and one `fuzz_<packet>.c` each.
pub fn c_harnesses(module: &Module, package: &str) -> Vec<(String, String)> {
    let opts = GenOptions { package: package.to_string(), ..GenOptions::default() };
    let guard = package.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    let mut files = vec![(format!("{}.h", package), generate_module(module, Language::C, &opts))];
    for name in targets(module) {
        let mut s = format!(
            "/* libFuzzer harness for {n}: a value decoded from any bytes, once encoded,\n \
             * must decode again and encode to the same bytes.\n *\n \
             *   clang -g -fsanitize=fuzzer,address fuzz_{l}.c -o fuzz_{l} && ./fuzz_{l}\n \
             *   cc -g -DPB_FUZZ_MAIN -fsanitize=address fuzz_{l}.c -o run_{l} && ./run_{l} input...\n */\n\
             #define {g}_IMPLEMENTATION\n#include \"{p}.h\"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n",
            n = name,
            l = name.to_ascii_lowercase(),
            g = guard,
            p = package
        );
        let _ = write!(
            s,
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n    \
             {n} p;\n    uint8_t *a = NULL, *b = NULL;\n    size_t an = 0, bn = 0;\n    \
             if ({n}_decode(&p, data, size) != PB_OK) return 0;\n    \
             if ({n}_encode(&p, &a, &an) != PB_OK) {{\n        {n}_free(&p);\n        return 0;\n    }}\n    {n}_free(&p);\n    \
             if ({n}_decode(&p, a, an) != PB_OK) abort();\n    \
             if ({n}_encode(&p, &b, &bn) != PB_OK) abort();\n    {n}_free(&p);\n    \
             if (an != bn || (an && memcmp(a, b, an) != 0)) abort();\n    free(a);\n    free(b);\n    return 0;\n}}\n",
            n = name
        );
        s.push_str(
            "\n#ifdef PB_FUZZ_MAIN\n/* Without libFuzzer: run each file named on the command line. */\n\
             int main(int argc, char **argv) {\n    int i;\n    for (i = 1; i < argc; i++) {\n        \
             FILE *f = fopen(argv[i], \"rb\");\n        uint8_t *buf;\n        long n;\n        \
             if (!f) { perror(argv[i]); return 1; }\n        fseek(f, 0, SEEK_END);\n        n = ftell(f);\n        \
             fseek(f, 0, SEEK_SET);\n        buf = (uint8_t *)malloc(n ? (size_t)n : 1);\n        \
             if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return 1; }\n        \
             fclose(f);\n        LLVMFuzzerTestOneInput(buf, (size_t)n);\n        free(buf);\n    }\n    return 0;\n}\n#endif\n",
        );
        files.push((format!("fuzz_{}.c", name.to_ascii_lowercase()), s));
    }
    files
}
