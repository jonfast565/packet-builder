//! Stream helpers: `tryDecode` (a packet, or how many more bytes are
//! needed) and `frameLen` (a packet's size from its header).

use super::decode::{part_value, read_raw};
use super::expr::store_value;
use super::naming::{Java, class_name};
use crate::generators::common::{Mode, Out, Scope};
use crate::ir::{Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = class_name(&p.name);
    out.line("");
    out.line("/**");
    out.line(" * Decode from a buffer that may end mid-packet (a stream): the packet and the");
    out.line(" * bytes it took, or how many more bytes are needed at least.");
    out.line(" */");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.open(format!("public static PbStatus<{}> tryDecode(byte[] data) {{", name));
        out.line("return tryDecode(data, 0);");
        out.close("}");
        out.line("");
        out.line("/** tryDecode as protocol version {@code version}; 0: the one in the data, or the latest. */");
        out.open(format!("public static PbStatus<{}> tryDecode(byte[] data, int version) {{", name));
        out.line("PbReader pbR = new PbReader(data);");
        out.line(format!("if (version != 0) pbR.setVersion(version, {}, {});", min, latest));
    } else {
        out.open(format!("public static PbStatus<{}> tryDecode(byte[] data) {{", name));
        out.line("PbReader pbR = new PbReader(data);");
    }
    out.open("try {");
    out.line(format!("{} p = decodeFrom(pbR);", name));
    out.line("return PbStatus.done(p, (int) ((pbR.positionBits() + 7) / 8));");
    out.close("} catch (PbException e) {");
    out.push();
    out.line("if (e.kind() != PbErrorKind.INCOMPLETE) throw e;");
    out.line("return PbStatus.incomplete((int) Math.max((e.neededBits() + 7) / 8, 1));");
    out.close("}");
    out.close("}");
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Java>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "/** The packet's size from its first {} byte(s), or empty until they are there. */",
        f.header_bytes
    ));
    out.open("public static java.util.OptionalInt frameLen(byte[] data) {");
    if f.header_bytes > 0 {
        out.line(format!("if (data.length < {}) return java.util.OptionalInt.empty();", f.header_bytes));
    }
    out.line(format!("{} p = new {}();", name, name));
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        match &h.when {
            Some(c) => out.open(format!("if ({}) {{", scope.expr(c))),
            None => out.open("{"),
        }
        out.line("PbReader pbR = new PbReader(data);");
        out.line(format!("pbR.skipBits({});", h.offset_bits));
        out.line(format!("long pbC = {};", read_raw(&h.container, h.container_bits)));
        out.line(format!("{} = {};", scope.field(m), part_value(&m.ty, h.shift, h.bits, h.signed)));
        out.close("}");
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.line(format!("if (data.length < {}) return java.util.OptionalInt.empty();", scope.expr(need)));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("{} = {};", scope.field(m), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("long pbN = {};", scope.expr(&f.total)));
    out.line("if (pbN < 0) throw new PbReader(data).error(PbErrorKind.INVALID, \"negative length \" + pbN);");
    out.line("return java.util.OptionalInt.of((int) pbN);");
    out.close("}");
}
