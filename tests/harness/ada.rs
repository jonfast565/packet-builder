use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::generators::ada::{ident, type_name, unit_name};
use packet_builder::ir::{Module, ValueType};
use packet_builder::{GenOptions, Language};
use serde_json::Value;

use super::{Case, Target, packet, run, which};

pub struct AdaTarget;

/// An Ada string expression: long text split into literals joined with `&`.
fn ada_text(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(200)
        .map(|c| format!("\"{}\"", c.iter().collect::<String>().replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join("\n        & ")
}

/// The value assigned by a `set`: real literals for floats, Unbounded
/// strings for text.
fn set_literal(v: &Value, ty: &ValueType) -> String {
    match v {
        Value::Number(n) if matches!(ty, ValueType::Float { .. }) => {
            let s = n.to_string();
            if s.contains('.') || s.contains('e') { s } else { format!("{}.0", s) }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("Ada.Strings.Unbounded.To_Unbounded_String ({})", ada_text(s)),
        other => panic!("set values must be numbers or strings, got {}", other),
    }
}

/// `gnatmake`, or `$GNATMAKE` when set.
fn gnatmake() -> Option<PathBuf> {
    match std::env::var_os("GNATMAKE") {
        Some(p) => Some(PathBuf::from(p)),
        None => which("gnatmake"),
    }
}

impl Target for AdaTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Ada)
    }

    fn unavailable(&self) -> Option<String> {
        if gnatmake().is_none() {
            return Some("gnatmake (GNAT) not found; set $GNATMAKE to use another".into());
        }
        which("gnatchop").is_none().then(|| "gnatchop (GNAT) not found".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        // No use clauses besides the package's own: packet records may be
        // named like declarations of Text_IO or Strings.Unbounded.
        let mut s = String::from("with Ada.Text_IO;\nwith Ada.Strings.Unbounded;\nwith Interfaces;\n");
        let unit = unit_name(&GenOptions::default());
        let _ = writeln!(s, "with {0}; use {0};\n", unit);
        s.push_str("procedure Harness is\n");
        s.push_str("   use type Ada.Strings.Unbounded.Unbounded_String;\n");
        s.push_str("   subtype Hx_Int is Interfaces.Integer_64;\n\n");
        s.push_str(
            "   function Hx_Bytes (S : String) return Pb_Byte_Array is\n      R : Pb_Byte_Array (0 .. S'Length / 2 - 1);\n   begin\n      for I in R'Range loop\n         R (I) := Interfaces.Unsigned_8'Value (\"16#\" & S (S'First + 2 * I .. S'First + 2 * I + 1) & \"#\");\n      end loop;\n      return R;\n   end Hx_Bytes;\n\n",
        );
        s.push_str(
            "   function Hx_Img (V : Hx_Int) return String is\n      S : constant String := Hx_Int'Image (V);\n   begin\n      if S (S'First) = ' ' then\n         return S (S'First + 1 .. S'Last);\n      end if;\n      return S;\n   end Hx_Img;\n\n",
        );
        s.push_str(
            "   function Hx_E (Pre : String) return String is\n      X : constant Pb_Error_Info := Last_Error;\n   begin\n      return \",\"\"\" & Pre & \"error\"\":\" & Pb_Json_Str (X.Message) & \",\"\"\" & Pre & \"kind\"\":\"\"\" & Pb_Kind_Name (X.Kind) & \"\"\",\"\"\" & Pre & \"path\"\":\" & Pb_Json_Str (X.Path);\n   end Hx_E;\n\n",
        );
        for (i, c) in cases.iter().enumerate() {
            let p = packet(module, &c.packet);
            let ty = type_name(&p.name);
            let ver = c.version.map(|v| format!(", Version => {}", v)).unwrap_or_default();
            let _ = writeln!(s, "   procedure Hx_Case_{} is", i);
            let _ = writeln!(s, "      Hx_D : constant Pb_Byte_Array := Hx_Bytes ({});", ada_text(&c.hex));
            let _ = writeln!(s, "      Hx_P : {};", ty);
            s.push_str("      Hx_Ok : Boolean := True;\n");
            s.push_str("      Hx_S : Ada.Strings.Unbounded.Unbounded_String;\n");
            if c.args.is_empty() {
                s.push_str("      Hx_N, Hx_F : Hx_Int := 0;\n");
            }
            s.push_str("   begin\n");
            let ver = format!("{}{}", c.more_args(), ver);
            let _ = writeln!(s, "      begin\n         Hx_P := Decode (Hx_D{});", ver);
            s.push_str("      exception\n         when Pb_Error =>\n            Hx_Ok := False;\n");
            s.push_str("            Ada.Text_IO.Put_Line (\"{\"\"ok\"\":false\" & Hx_E (\"\") & \"}\");\n      end;\n");
            s.push_str("      if Hx_Ok then\n");
            for (name, v) in &c.set {
                let path = super::resolve_path(module, p, name);
                let ty = &path.last().expect("a set path has a member").1.ty;
                let _ = writeln!(
                    s,
                    "         Hx_P.{} := {};",
                    super::accessor(module, p, name, |_, m| ident(&m.name)),
                    set_literal(v, ty)
                );
            }
            s.push_str("         declare\n            Hx_V : constant String := To_Json (Hx_P);\n         begin\n");
            let _ = writeln!(
                s,
                "            Ada.Text_IO.Put_Line (\"{{\"\"ok\"\":true,\"\"value\"\":\" & Hx_V & \",\"\"encoded\"\":\" & Pb_Json_Hex (Encode (Hx_P{})) & \"}}\");",
                ver
            );
            s.push_str("         exception\n            when Pb_Error =>\n");
            s.push_str(
                "               Ada.Text_IO.Put_Line (\"{\"\"ok\"\":true,\"\"value\"\":\" & Hx_V & Hx_E (\"encode_\") & \"}\");\n",
            );
            s.push_str("         end;\n      end if;\n");
            if !c.args.is_empty() {
                s.push_str("      Hx_S := Ada.Strings.Unbounded.To_Unbounded_String (\"{\");\n");
                s.push_str("      Ada.Text_IO.Put_Line (Ada.Strings.Unbounded.To_String (Hx_S) & \"}\");\n");
                let _ = writeln!(s, "   end Hx_Case_{};\n", i);
                continue;
            }
            let _ = writeln!(s, "      declare\n         Hx_Q : {};\n      begin", ty);
            let _ = writeln!(s, "         if Try_Decode (Hx_D, Hx_Q, Hx_N{}) then", ver);
            s.push_str(
                "            Hx_S := Ada.Strings.Unbounded.To_Unbounded_String (\"{\"\"try\"\":\"\"done\"\",\"\"n\"\":\" & Hx_Img (Hx_N));\n",
            );
            s.push_str("         else\n");
            s.push_str(
                "            Hx_S := Ada.Strings.Unbounded.To_Unbounded_String (\"{\"\"try\"\":\"\"incomplete\"\",\"\"n\"\":\" & Hx_Img (Hx_N));\n",
            );
            s.push_str("         end if;\n      exception\n         when Pb_Error =>\n");
            s.push_str(
                "            Hx_S := Ada.Strings.Unbounded.To_Unbounded_String (\"{\"\"try\"\":\"\"error\"\"\");\n",
            );
            s.push_str("      end;\n");
            if super::has_frame(module, p) {
                let _ = writeln!(s, "      begin\n         if {}_Frame_Len (Hx_D, Hx_F) then", ty);
                s.push_str("            Hx_S := Hx_S & \",\"\"frame\"\":\" & Hx_Img (Hx_F);\n");
                s.push_str("         else\n            Hx_S := Hx_S & \",\"\"frame\"\":null\";\n         end if;\n");
                s.push_str("      exception\n         when Pb_Error =>\n");
                s.push_str("            Hx_S := Hx_S & \",\"\"frame\"\":\"\"error\"\"\";\n      end;\n");
            }
            s.push_str("      Ada.Text_IO.Put_Line (Ada.Strings.Unbounded.To_String (Hx_S) & \"}\");\n");
            let _ = writeln!(s, "   end Hx_Case_{};\n", i);
        }
        s.push_str("begin\n");
        for i in 0..cases.len() {
            let _ = writeln!(s, "   Hx_Case_{};", i);
        }
        if cases.is_empty() {
            s.push_str("   null;\n");
        }
        s.push_str("end Harness;\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        // One file holds the spec and the body; gnatchop splits it into
        // <unit>.ads and <unit>.adb.
        let source = format!("{}.ada", unit_name(&GenOptions::default()).to_ascii_lowercase());
        fs::write(dir.join(&source), generated).unwrap();
        fs::write(dir.join("harness.adb"), harness).unwrap();
        run(Command::new("gnatchop").current_dir(dir).args(["-w", &source]), "gnatchop")?;
        let gnatmake = gnatmake().expect("checked by unavailable");
        let mut cmd = Command::new(gnatmake);
        cmd.current_dir(dir).args(["-q", "-gnat2012", "-gnata", "harness.adb"]);
        mac_sdk(&mut cmd);
        run(&mut cmd, "gnatmake")?;
        run(&mut Command::new(dir.join("harness")), "ada harness")
    }
}

/// On macOS GNAT's linker needs the SDK (libSystem): set `SDKROOT` and
/// `LIBRARY_PATH` from `xcrun --show-sdk-path` unless `SDKROOT` is set.
fn mac_sdk(cmd: &mut Command) {
    if !cfg!(target_os = "macos") || std::env::var_os("SDKROOT").is_some() {
        return;
    }
    let Ok(out) = Command::new("xcrun").arg("--show-sdk-path").output() else { return };
    let sdk = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || sdk.is_empty() {
        return;
    }
    let lib = match std::env::var("LIBRARY_PATH") {
        Ok(old) if !old.is_empty() => format!("{}/usr/lib:{}", sdk, old),
        _ => format!("{}/usr/lib", sdk),
    };
    cmd.env("SDKROOT", &sdk).env("LIBRARY_PATH", lib);
}
