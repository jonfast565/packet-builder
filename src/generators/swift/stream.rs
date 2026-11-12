//! Stream helpers: `tryDecode` (a packet, or how many more bytes are
//! needed) and `frameLen` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{Swift, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

/// The body of `tryDecode` once `pbR` is set up.
fn try_body(out: &mut Out, name: &str) {
    out.open("do {");
    out.line(format!("let p = try {}.decodeFrom(pbR)", name));
    out.line("return .done(p, (pbR.positionBits() + 7) / 8)");
    out.close("} catch let e as PbError where e.kind == .incomplete {");
    out.push();
    out.line("return .incomplete(Swift.max((e.neededBits + 7) / 8, 1))");
    out.close("}");
}

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = &p.name;
    out.line("");
    out.line("/// Decode from a buffer that may end mid-packet (a stream): the packet and");
    out.line("/// the bytes it took, or how many more bytes are needed at least.");
    out.open(format!("public static func tryDecode(_ data: [UInt8]) throws -> PbStatus<{}> {{", name));
    out.line("let pbR = PbReader(data)");
    try_body(out, name);
    out.close("}");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line("");
        out.line("/// `tryDecode` as protocol version `version`.");
        out.open(format!(
            "public static func tryDecode(_ data: [UInt8], version: Int) throws -> PbStatus<{}> {{",
            name
        ));
        out.line("let pbR = PbReader(data)");
        out.line(format!("try pbR.setVersion(Int64(version), {}, {})", min, latest));
        try_body(out, name);
        out.close("}");
    }
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Swift>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "/// The size of the packet at the start of `data`, from its first {} byte(s); nil until",
        f.header_bytes
    ));
    out.line("/// they are there.");
    out.open("public static func frameLen(_ data: [UInt8]) throws -> Int? {");
    if f.header_bytes > 0 {
        out.line(format!("if data.count < {} {{ return nil }}", f.header_bytes));
    }
    // The body goes to its own buffer first: version expressions read
    // `pbR` (always the latest version here), declared only when used.
    let mut body = Out::new("    ");
    let out_fn = out;
    let out = &mut body;
    let uses_p = !f.fields.is_empty() || !f.calcs.is_empty();
    if uses_p {
        out.line(format!("var p = {}()", name));
    }
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        match &h.when {
            Some(c) => out.open(format!("if {} {{", scope.expr(c))),
            None => out.open("do {"),
        }
        out.line("let pbH = PbReader(data)");
        out.line(format!("try pbH.skipBits({})", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pbH.readUInt({}, {})", nbytes, Swift::little(endian)),
            _ => format!("pbH.readBits({})", h.container_bits),
        };
        out.line(format!("let pb_c: UInt64 = try {}", raw));
        let bits = format!("((pb_c >> {}) & 0x{:x})", h.shift, mask(h.bits));
        let v = if h.signed { format!("pbSext({}, {})", bits, h.bits) } else { bits };
        out.line(format!("p.{} = {}(truncatingIfNeeded: {})", ident(&m.name), scalar_type(&m.ty), v));
        out.close("}");
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.line(format!("if Int64(data.count) < {} {{ return nil }}", scope.expr(need)));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p.{} = {}", ident(&m.name), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("return try pbFrameSize({})", scope.expr(&f.total)));
    if body.buf.contains("pbR.") {
        out_fn.line("let pbR = PbReader(data)");
    }
    out_fn.line(body.buf.trim_end());
    out_fn.close("}");
}
