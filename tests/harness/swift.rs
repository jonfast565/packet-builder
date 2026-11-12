use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::swift::ident;
use packet_builder::ir::Module;

use super::{Case, Target, packet, run, set_literal, which};

pub struct SwiftTarget;

/// The driver is data-driven: one function per packet (with a `switch` over
/// the `set` lists its cases use) and a table of `packet set version hex`
/// lines, which keeps the Swift type checker fast for thousands of cases.
impl Target for SwiftTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Swift)
    }

    fn unavailable(&self) -> Option<String> {
        which("swiftc").is_none().then(|| "swiftc not found on PATH".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("import Foundation\n\n");
        s.push_str(
            r#"func pbUnhex(_ s: Substring) -> [UInt8] {
    var out: [UInt8] = []
    var hi: UInt8? = nil
    for c in s.utf8 {
        let v: UInt8 = c <= 57 ? c - 48 : (c | 0x20) - 87
        if let h = hi { out.append(h << 4 | v); hi = nil } else { hi = v }
    }
    return out
}

func pbE(_ e: Error, _ pre: String) -> String {
    if let e = e as? PbError {
        return "\"\(pre)error\":\(pbJsonStr(e.description)),\"\(pre)kind\":\(pbJsonStr(e.kind.rawValue)),\"\(pre)path\":\(pbJsonStr(e.path))"
    }
    return "\"\(pre)error\":\(pbJsonStr("\(e)"))"
}

func pbStream<T>(_ f: () throws -> PbStatus<T>) -> String {
    do {
        switch try f() {
        case .done(_, let n): return "{\"try\":\"done\",\"n\":\(n)"
        case .incomplete(let n): return "{\"try\":\"incomplete\",\"n\":\(n)"
        }
    } catch {
        return "{\"try\":\"error\""
    }
}

func pbFrame(_ f: () throws -> Int?) -> String {
    do {
        if let n = try f() { return ",\"frame\":\(n)" }
        return ",\"frame\":null"
    } catch {
        return ",\"frame\":\"error\""
    }
}

"#,
        );

        // Per packet: the distinct `set` lists of its cases, numbered from 1.
        let mut sets: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut table = String::new();
        for c in cases {
            let p = packet(module, &c.packet);
            let lists = sets.entry(&p.name).or_default();
            let mut index = 0;
            if !c.set.is_empty() {
                let mut body = String::new();
                for (name, v) in &c.set {
                    let place = super::accessor(module, p, name, |_, m| ident(&m.name));
                    let _ = write!(body, "p.{} = {}; ", place, set_literal(v));
                }
                index = match lists.iter().position(|l| *l == body) {
                    Some(i) => i + 1,
                    None => {
                        lists.push(body);
                        lists.len()
                    }
                };
            }
            let ver = c.version.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
            let _ = writeln!(table, "{} {} {} {}", p.name, index, ver, c.hex);
        }

        for (name, lists) in &sets {
            let p = packet(module, name);
            let versioned = p.versions.is_some();
            let call = |plain: &str, with_version: &str| {
                if versioned { format!("(ver == nil ? {} : {})", plain, with_version) } else { plain.to_string() }
            };
            let _ = writeln!(s, "func run_{}(_ d: [UInt8], _ ver: Int?, _ set: Int) {{", name);
            s.push_str("    var line: String\n    do {\n");
            let _ = writeln!(
                s,
                "        {} p = try {}",
                if lists.is_empty() { "let" } else { "var" },
                call(&format!("{}.decode(d)", name), &format!("{}.decode(d, version: ver!)", name))
            );
            if !lists.is_empty() {
                s.push_str("        switch set {\n");
                for (i, body) in lists.iter().enumerate() {
                    let _ = writeln!(s, "        case {}: {}", i + 1, body);
                }
                s.push_str("        default: break\n        }\n");
            }
            s.push_str("        let v = p.toJson()\n        do {\n");
            let _ = writeln!(s, "            let b = try {}", call("p.encode()", "p.encode(version: ver!)"));
            s.push_str(
                "            line = \"{\\\"ok\\\":true,\\\"value\\\":\\(v),\\\"encoded\\\":\\(pbJsonHex(b))}\"\n",
            );
            s.push_str("        } catch {\n");
            s.push_str("            line = \"{\\\"ok\\\":true,\\\"value\\\":\\(v),\\(pbE(error, \"encode_\"))}\"\n");
            s.push_str("        }\n        _ = p\n    } catch {\n");
            s.push_str("        line = \"{\\\"ok\\\":false,\\(pbE(error, \"\"))}\"\n    }\n");
            s.push_str("    print(line)\n");
            let frame = super::has_frame(module, p);
            let _ = writeln!(
                s,
                "    {} st = pbStream {{ try {} }}",
                if frame { "var" } else { "let" },
                call(&format!("{}.tryDecode(d)", name), &format!("{}.tryDecode(d, version: ver!)", name))
            );
            if frame {
                let _ = writeln!(s, "    st += pbFrame {{ try {}.frameLen(d) }}", name);
            }
            s.push_str("    print(st + \"}\")\n}\n\n");
        }

        s.push_str("let pbCases = \"\"\"\n");
        s.push_str(&table);
        s.push_str("\"\"\"\n\n");
        s.push_str("for row in pbCases.split(separator: \"\\n\") {\n");
        s.push_str("    let f = row.split(separator: \" \", omittingEmptySubsequences: false)\n");
        s.push_str("    let set = Int(f[1]) ?? 0\n");
        s.push_str("    let ver: Int? = f[2] == \"-\" ? nil : Int(f[2])\n");
        s.push_str("    let d = pbUnhex(f.count > 3 ? f[3] : \"\")\n");
        s.push_str("    switch f[0] {\n");
        for name in sets.keys() {
            let _ = writeln!(s, "    case \"{}\": run_{}(d, ver, set)", name, name);
        }
        s.push_str("    default: print(\"unknown packet \\(f[0])\")\n    }\n}\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.swift"), generated).unwrap();
        fs::write(dir.join("main.swift"), harness).unwrap();
        // Unoptimised build: integer overflow and out-of-range indexing in
        // generated code trap.
        run(
            Command::new("swiftc").current_dir(dir).args([
                "-swift-version",
                "5",
                "-Onone",
                "-suppress-warnings",
                "-module-name",
                "pbharness",
                "packets.swift",
                "main.swift",
                "-o",
                "harness",
            ]),
            "swiftc",
        )?;
        run(&mut Command::new(dir.join("harness")), "swift harness")
    }
}
