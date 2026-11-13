use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use packet_builder::generators::pascal::{ident, type_name, unit_name};
use packet_builder::ir::Module;
use packet_builder::{GenOptions, Language};
use serde_json::Value;

use super::{Case, Target, packet, run, which};

pub struct PascalTarget;

/// A Pascal string expression: long text split into literals joined with
/// `+` (Delphi limits a literal to 255 characters).
fn pas_text(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(200)
        .map(|c| format!("'{}'", c.iter().collect::<String>().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(" + ")
}

fn set_literal(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => pas_text(s),
        other => panic!("set values must be numbers or strings, got {}", other),
    }
}

impl Target for PascalTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Pascal)
    }

    fn unavailable(&self) -> Option<String> {
        which("fpc").is_none().then(|| "fpc (Free Pascal) not found".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("program harness;\n\n{$IFDEF FPC}{$MODE DELPHIUNICODE}{$ENDIF}\n\n");
        let _ = writeln!(s, "uses\n  SysUtils, {};\n", unit_name(&GenOptions::default()));
        s.push_str(
            "function HexBytes(const S: string): TBytes;\nvar\n  I: Integer;\nbegin\n  SetLength(Result, Length(S) div 2);\n  for I := 0 to High(Result) do\n    Result[I] := StrToInt('$' + Copy(S, 2 * I + 1, 2));\nend;\n\n",
        );
        s.push_str(
            "function E(Err: EPbError; const Pre: string): string;\nbegin\n  Result := ',\"' + Pre + 'error\":' + PbJsonStr(Err.Message) + ',\"' + Pre + 'kind\":\"' + PbKindName(Err.Kind) + '\",\"' + Pre + 'path\":' + PbJsonStr(Err.Path);\nend;\n\n",
        );
        if cases.iter().any(|c| c.source) {
            // The fetch callback of a source case: refuses the unread range.
            s.push_str(
                "type\n  TCaseSource = class\n    D: TBytes;\n    UFrom, UTo: Int64;\n    procedure Fetch(AOffset: Int64; var Buf: array of Byte);\n  end;\n\n",
            );
            s.push_str(
                "procedure TCaseSource.Fetch(AOffset: Int64; var Buf: array of Byte);\nvar\n  A, B: Int64;\nbegin\n  A := AOffset;\n  if UFrom > A then\n    A := UFrom;\n  B := AOffset + Length(Buf);\n  if UTo < B then\n    B := UTo;\n  if A < B then\n    raise Exception.Create('fetched an unread byte');\n  if Length(Buf) > 0 then\n    Move(D[AOffset], Buf[0], Length(Buf));\nend;\n\n",
            );
        }
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let class = type_name(&p.name);
            let ver = c.version.map(|v| format!(", {}", v)).unwrap_or_default();
            let _ = writeln!(s, "procedure Case{};", i);
            let _ = writeln!(s, "var\n  p: {};\n  v, s: string;\n  b, d: TBytes;\n  n, f: Integer;", class);
            if c.source {
                s.push_str("  cs: TCaseSource;\n  src: TPbSource;\n  r: TPbReader;\n");
            }
            s.push_str("begin\n");
            let _ = writeln!(s, "  d := HexBytes({});", pas_text(&c.hex));
            s.push_str("  p := nil;\n  try\n    try\n");
            if c.source {
                let (from, to) = c.unread.unwrap_or((0, 0));
                s.push_str("      cs := TCaseSource.Create;\n      cs.D := d;\n");
                let _ = writeln!(s, "      cs.UFrom := {};\n      cs.UTo := {};", from, to);
                let _ = writeln!(s, "      src := TPbSource.Create(Length(d), {}, cs.Fetch);", super::SOURCE_PAGE);
                s.push_str("      r := TPbReader.CreateFromSource(src);\n      try\n");
                let _ = writeln!(s, "        p := {}.DecodeFrom(r);", class);
                s.push_str("      finally\n        r.Free;\n        src.Free;\n        cs.Free;\n      end;\n");
            } else {
                let _ = writeln!(s, "      p := {}.Decode(d{}{});", class, c.more_args(), ver);
            }
            s.push_str("    except\n      on Err: EPbError do\n        WriteLn('{\"ok\":false' + E(Err, '') + '}');\n    end;\n");
            s.push_str("    if p <> nil then\n    begin\n");
            for (name, v) in &c.set {
                let _ = writeln!(
                    s,
                    "      p.{} := {};",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    set_literal(v)
                );
            }
            s.push_str("      v := p.ToJson;\n      try\n");
            let enc = c.args_then(&ver);
            let enc = if enc.is_empty() { enc } else { format!("({})", enc) };
            let _ = writeln!(s, "        b := p.Encode{};", enc);
            s.push_str("        WriteLn('{\"ok\":true,\"value\":' + v + ',\"encoded\":' + PbJsonHex(b) + '}');\n");
            s.push_str("      except\n        on Err: EPbError do\n          WriteLn('{\"ok\":true,\"value\":' + v + E(Err, 'encode_') + '}');\n      end;\n    end;\n");
            s.push_str("  finally\n    FreeAndNil(p);\n  end;\n");
            if !c.args.is_empty() {
                s.push_str("  WriteLn('{}');\n  v := '';\n  b := nil;\nend;\n\n");
                continue;
            }
            s.push_str("  try\n");
            let _ = writeln!(s, "    if {}.TryDecode(d, p, n{}) then", class, ver);
            s.push_str(
                "    begin\n      s := '{\"try\":\"done\",\"n\":' + IntToStr(n);\n      FreeAndNil(p);\n    end\n",
            );
            s.push_str("    else\n      s := '{\"try\":\"incomplete\",\"n\":' + IntToStr(n);\n");
            s.push_str("  except\n    on EPbError do\n      s := '{\"try\":\"error\"';\n  end;\n");
            if super::has_frame(module, p) {
                s.push_str("  try\n");
                let _ = writeln!(s, "    if {}.FrameLen(d, f) then", class);
                s.push_str("      s := s + ',\"frame\":' + IntToStr(f)\n    else\n      s := s + ',\"frame\":null';\n");
                s.push_str("  except\n    on EPbError do\n      s := s + ',\"frame\":\"error\"';\n  end;\n");
            } else {
                s.push_str("  f := 0;\n");
            }
            s.push_str("  WriteLn(s + '}');\n  if f < 0 then WriteLn;\n  v := '';\n  b := nil;\nend;\n\n");
        }
        s.push_str("begin\n");
        for i in 0..cases.len() {
            let _ = writeln!(s, "  Case{};", i);
        }
        s.push_str("end.\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        let unit = format!("{}.pas", unit_name(&GenOptions::default()));
        fs::write(dir.join(unit), generated).unwrap();
        fs::write(dir.join("harness.pas"), harness).unwrap();
        // -gh links heaptrc, which reports what the run left allocated:
        // every error path must free the packets it built.
        run(Command::new("fpc").current_dir(dir).args(["-Mdelphiunicode", "-ve", "-gh", "harness.pas"]), "fpc")?;
        let heap = dir.join("heap.txt");
        let stdout =
            run(Command::new(dir.join("harness")).env("HEAPTRC", format!("log={}", heap.display())), "pascal harness")?;
        let report = fs::read_to_string(&heap).unwrap_or_default();
        if !report.lines().any(|l| l.starts_with("0 unfreed memory blocks")) {
            return Err(format!("pascal harness leaked memory:\n{}", report));
        }
        Ok(stdout)
    }
}
