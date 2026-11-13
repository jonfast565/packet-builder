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
/// the `set` lists its cases use) and a table of `packet set version args
/// hex` lines, which keeps the Swift type checker fast for thousands of cases.
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

struct PbUnread: Error, CustomStringConvertible {
    var description: String { return "fetched an unread byte" }
}

/// A source over `d` whose fetch fails on bytes `u[0]..<u[1]` (when given).
func pbSource(_ d: [UInt8], _ u: [Int]) -> PbSource {
    return PbSource(count: d.count, page: @PAGE@) { at, buf in
        if u.count == 2 && max(at, u[0]) < min(at + buf.count, u[1]) {
            throw PbUnread()
        }
        buf.copyBytes(from: d[at..<at + buf.count])
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
        s = s.replace("@PAGE@", &super::SOURCE_PAGE.to_string());

        // Per packet: the distinct `set` lists of its cases, numbered from 1.
        let mut sets: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut table = String::new();
        let mut sourced: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
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
            let args = if c.args.is_empty() { "-".to_string() } else { c.arg_list().replace(' ', "") };
            // "-": a buffer; "*": a source; "from,to": a source that must not fetch those bytes.
            let src = match (c.source, c.unread) {
                (false, _) => "-".to_string(),
                (true, None) => "*".to_string(),
                (true, Some((from, to))) => format!("{},{}", from, to),
            };
            if c.source {
                sourced.insert(p.name.as_str());
            }
            let _ = writeln!(table, "{} {} {} {} {} {}", p.name, index, ver, args, src, c.hex);
        }

        for (name, lists) in &sets {
            let p = packet(module, name);
            let versioned = p.versions.is_some();
            let call = |plain: &str, with_version: &str| {
                if versioned { format!("(ver == nil ? {} : {})", plain, with_version) } else { plain.to_string() }
            };
            // Arguments of a packet with parameters (after the version).
            let pargs: Vec<String> = (0..p.params.len()).map(|i| format!("numericCast(a[{}])", i)).collect();
            let more: String = pargs.iter().map(|a| format!(", {}", a)).collect();
            let _ = writeln!(s, "func run_{}(_ d: [UInt8], _ ver: Int?, _ set: Int, _ a: [Int], _ u: [Int]?) {{", name);
            if pargs.is_empty() {
                s.push_str(
                    "    _ = a
",
                );
            }
            s.push_str("    var line: String\n    do {\n");
            let mut decode =
                call(&format!("{}.decode(d{})", name, more), &format!("{}.decode(d, version: ver!{})", name, more));
            if sourced.contains(name) {
                decode = format!("(u == nil ? {} : {}.decodeFrom(PbReader(source: pbSource(d, u!))))", decode, name);
            } else {
                s.push_str("        _ = u\n");
            }
            let _ = writeln!(s, "        {} p = try {}", if lists.is_empty() { "let" } else { "var" }, decode);
            if !lists.is_empty() {
                s.push_str("        switch set {\n");
                for (i, body) in lists.iter().enumerate() {
                    let _ = writeln!(s, "        case {}: {}", i + 1, body);
                }
                s.push_str("        default: break\n        }\n");
            }
            s.push_str("        let v = p.toJson()\n        do {\n");
            let _ = writeln!(
                s,
                "            let b = try {}",
                call(&format!("p.encode({})", pargs.join(", ")), &format!("p.encode(version: ver!{})", more))
            );
            s.push_str(
                "            line = \"{\\\"ok\\\":true,\\\"value\\\":\\(v),\\\"encoded\\\":\\(pbJsonHex(b))}\"\n",
            );
            s.push_str("        } catch {\n");
            s.push_str("            line = \"{\\\"ok\\\":true,\\\"value\\\":\\(v),\\(pbE(error, \"encode_\"))}\"\n");
            s.push_str("        }\n        _ = p\n    } catch {\n");
            s.push_str("        line = \"{\\\"ok\\\":false,\\(pbE(error, \"\"))}\"\n    }\n");
            s.push_str("    print(line)\n");
            if !p.params.is_empty() {
                s.push_str("    print(\"{}\")\n}\n\n");
                continue;
            }
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
        s.push_str("    let a = f[3] == \"-\" ? [] : f[3].split(separator: \",\").map { Int($0)! }\n");
        s.push_str("    let u: [Int]? = f[4] == \"-\" ? nil : f[4] == \"*\" ? [] : f[4].split(separator: \",\").map { Int($0)! }\n");
        s.push_str("    let d = pbUnhex(f.count > 5 ? f[5] : \"\")\n");
        s.push_str("    switch f[0] {\n");
        for name in sets.keys() {
            let _ = writeln!(s, "    case \"{}\": run_{}(d, ver, set, a, u)", name, name);
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
