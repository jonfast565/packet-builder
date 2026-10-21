//! Stream helpers: `TryDecode` (a packet, or how many more bytes are
//! needed) and `FrameLen` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{CSharp, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = &p.name;
    out.line("");
    out.line("/// <summary>Decode from a buffer that may end mid-packet (a stream): the packet and the");
    out.line("/// bytes it took, or how many more bytes are needed at least.</summary>");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line(format!("public static PbStatus<{}> TryDecode(byte[] data, int version = 0)", name));
        out.open("{");
        out.line("var pbR = new PbReader(data);");
        out.line(format!("if (version != 0) pbR.SetVersion(version, {}, {});", min, latest));
    } else {
        out.line(format!("public static PbStatus<{}> TryDecode(byte[] data)", name));
        out.open("{");
        out.line("var pbR = new PbReader(data);");
    }
    out.line("try");
    out.open("{");
    out.line("var p = DecodeFrom(pbR);");
    out.line(format!("return PbStatus<{}>.Done(p, (int)((pbR.PositionBits + 7) / 8));", name));
    out.close("}");
    out.line("catch (PbException e) when (e.Kind == PbErrorKind.Incomplete)");
    out.open("{");
    out.line(format!("return PbStatus<{}>.Incomplete((int)Math.Max((e.NeededBits + 7) / 8, 1));", name));
    out.close("}");
    out.close("}");
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<CSharp>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "/// <summary>The packet's size from its first {} byte(s), or null until they are there.</summary>",
        f.header_bytes
    ));
    out.line("public static int? FrameLen(byte[] data)");
    out.open("{");
    if f.header_bytes > 0 {
        out.line(format!("if (data.Length < {}) return null;", f.header_bytes));
    }
    out.line(format!("var p = new {}();", name));
    for h in &f.fields {
        let m = &p.members[h.member];
        out.open("{");
        out.line("var pbR = new PbReader(data);");
        out.line(format!("pbR.SkipBits({});", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, CSharp::little(endian)),
            _ => format!("pbR.ReadBits({})", h.container_bits),
        };
        out.line(format!("ulong pbC = {};", raw));
        let bits = format!("((pbC >> {}) & 0x{:x}UL)", h.shift, mask(h.bits));
        let st = scalar_type(&m.ty);
        let v = if h.signed {
            format!("unchecked(({})Pb.Sext({}, {}))", st, bits, h.bits)
        } else {
            format!("unchecked(({}){})", st, bits)
        };
        out.line(format!("{} = {};", scope.field(m), v));
        out.close("}");
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("{} = {};", scope.field(m), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("long pbN = {};", scope.expr(&f.total)));
    out.line("if (pbN < 0) throw new PbReader(data).Error(PbErrorKind.Invalid, $\"negative length {pbN}\");");
    out.line("return (int)pbN;");
    out.close("}");
}
