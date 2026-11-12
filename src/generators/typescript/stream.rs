//! Stream helpers: `tryDecode` (a packet, or how many more bytes are
//! needed) and `frameLen` (a packet's size from its header).

use super::decode::{extract, into, read_raw};
use super::expr::store_value;
use super::naming::{TypeScript, ident, type_name};
use crate::generators::common::{Mode, Out, Scope};
use crate::ir::{Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = type_name(&p.name);
    let versioned = p.versions.is_some();
    let arg = if versioned { ", version?: number" } else { "" };
    out.line("");
    out.line("/** Decode from a buffer that may end mid-packet (a stream): [packet, bytes");
    out.line(" * taken], or [null, n] when at least n more bytes are needed. */");
    out.open(format!("static tryDecode(data: Uint8Array{}): [{} | null, number] {{", arg, name));
    out.line("const pb_r = new PbReader(data);");
    if versioned {
        let (min, latest) = p.version_bounds();
        out.line(format!("if (version !== undefined) pb_r.setVersion(version, {}, {});", min, latest));
    }
    out.line(format!("let p: {};", name));
    out.open("try {");
    out.line(format!("p = {}.decodeFrom(pb_r);", name));
    out.close("} catch (e) {");
    out.push();
    out.open("if (e instanceof PbError && e.kind === PbError.INCOMPLETE) {");
    out.line("return [null, Math.max(Math.ceil(e.neededBits / 8), 1)];");
    out.close("}");
    out.line("throw e;");
    out.close("}");
    out.line("return [p, Math.ceil(pb_r.positionBits() / 8)];");
    out.close("}");
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<TypeScript>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "/** The packet's size from its first {} byte(s), or null until they are there. */",
        f.header_bytes
    ));
    out.open("static frameLen(data: Uint8Array): number | null {");
    if f.header_bytes > 0 {
        out.line(format!("if (data.length < {}) return null;", f.header_bytes));
    }
    out.line(format!("const p = new {}();", name));
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            out.open(format!("if ({}) {{", scope.expr(c)));
        } else {
            out.open("{");
        }
        out.line("const pb_r = new PbReader(data);");
        out.line(format!("pb_r.skipBits({});", h.offset_bits));
        let (raw, repr) = read_raw(&h.container, h.container_bits);
        out.line(format!("const pb_c = {};", raw));
        let (v, r) = extract("pb_c", repr, h.shift, h.bits, h.signed);
        out.line(format!("p.{} = {};", ident(&m.name), into(v, r, &m.ty)));
        out.close("}");
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.line(format!("if (BigInt(data.length) < {}) return null;", scope.expr(need)));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p.{} = {};", ident(&m.name), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("const pb_n = {};", scope.expr(&f.total)));
    out.line("if (pb_n < 0n) throw new PbReader(data).error(PbError.INVALID, \"negative length \" + pb_n);");
    out.line("return Number(pb_n);");
    out.close("}");
}
