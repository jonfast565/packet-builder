//! Stream helpers: `TryDecode` (a packet, or how many more bytes are
//! needed) and `FrameLen` (a packet's size from its header).

use super::decode::bits_value;
use super::expr::store_value;
use super::naming::{Pascal, type_name};
use crate::generators::common::{Dialect, Mode, Out, Scope};
use crate::ir::{Codec, Module, Packet};

fn version_param(p: &Packet, defaults: bool) -> String {
    match p.versions {
        Some(_) => format!("; AVersion: Integer{}", if defaults { " = 0" } else { "" }),
        None => String::new(),
    }
}

pub fn declare_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = type_name(&p.name);
    out.line("/// Decode from a buffer that may end mid-packet (a stream). True: AValue and the");
    out.line("/// ACount bytes it took; False: ACount more bytes are needed at least.");
    out.line(format!(
        "class function TryDecode(const AData: TBytes; out AValue: {}; out ACount: Integer{}): Boolean;",
        name,
        version_param(p, true)
    ));
    if let Some(f) = module.frame_length(p) {
        out.line(format!(
            "/// The packet's size from its first {} byte(s); False until they are there.",
            f.header_bytes
        ));
        out.line("class function FrameLen(const AData: TBytes; out ALength: Integer): Boolean;");
    }
}

pub fn implement_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = type_name(&p.name);
    out.line("");
    out.line(format!(
        "class function {}.TryDecode(const AData: TBytes; out AValue: {}; out ACount: Integer{}): Boolean;",
        name,
        name,
        version_param(p, false)
    ));
    out.open("var");
    out.line("pbR: TPbReader;");
    out.pop();
    out.open("begin");
    out.line("AValue := nil;");
    out.line("ACount := 0;");
    out.line("pbR := TPbReader.Create(AData);");
    out.open("try");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line(format!("if AVersion <> 0 then pbR.SetVersion(AVersion, {}, {});", min, latest));
    }
    out.open("try");
    out.line("AValue := DecodeFrom(pbR);");
    out.line("ACount := Integer((pbR.PositionBits + 7) div 8);");
    out.line("Result := True;");
    out.close("except");
    out.push();
    out.line("on E: EPbError do");
    out.open("begin");
    out.line("if E.Kind <> pekIncomplete then raise;");
    out.line("ACount := Integer(PbMaxI((E.NeededBits + 7) div 8, 1));");
    out.line("Result := False;");
    out.close("end;");
    out.close("end;");
    out.close("finally");
    out.push();
    out.line("pbR.Free;");
    out.close("end;");
    out.close("end;");

    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Pascal>::new(p, Mode::Decode);
    out.line("");
    out.line(format!("class function {}.FrameLen(const AData: TBytes; out ALength: Integer): Boolean;", name));
    out.open("var");
    out.line(format!("p: {};", name));
    out.line("pbR: TPbReader;");
    out.line("pbC: UInt64;");
    out.line("pbN: Int64;");
    out.pop();
    out.open("begin");
    out.line("ALength := 0;");
    out.line("Result := False;");
    if f.header_bytes > 0 {
        out.line(format!("if Length(AData) < {} then Exit;", f.header_bytes));
    }
    out.line("pbR := nil;");
    out.line(format!("p := {}.Create;", name));
    out.open("try");
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            out.line(format!("if {} then", scope.expr(c)));
        }
        out.open("begin");
        out.line("pbR := TPbReader.Create(AData);");
        out.line(format!("pbR.SkipBits({});", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, Pascal::little(endian)),
            _ => format!("pbR.ReadBits({})", h.container_bits),
        };
        out.line(format!("pbC := {};", raw));
        out.line("FreeAndNil(pbR);");
        out.line(format!("{} := {};", scope.field(m), bits_value(&m.ty, "pbC", h.shift, h.bits, h.signed)));
        out.close("end;");
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.line(format!("if Length(AData) < {} then Exit;", scope.expr(need)));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("{} := {};", scope.field(m), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("pbN := {};", scope.expr(&f.total)));
    out.line("if pbN < 0 then raise EPbError.CreatePb(pekInvalid, 'negative length ' + IntToStr(pbN), '', 0);");
    out.line("ALength := Integer(pbN);");
    out.line("Result := True;");
    out.close("finally");
    out.push();
    out.line("pbR.Free;");
    out.line("p.Free;");
    out.close("end;");
    out.close("end;");
}
