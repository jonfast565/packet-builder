//! Stream helpers: `try_decode` (a packet, or how many more bytes are
//! needed) and `frame_len` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{Python, ident};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    out.line("@classmethod");
    let versioned = p.versions.is_some();
    let arg = if versioned { ", version=None" } else { "" };
    out.open(format!("def try_decode(cls, data{}) -> \"Tuple[Optional[{}], int]\":", arg, p.name));
    out.line("\"\"\"Decode from a buffer that may end mid-packet (a stream): (packet, bytes");
    out.line("taken), or (None, n) when at least n more bytes are needed.\"\"\"");
    out.line("pb_r = PbReader(data)");
    if versioned {
        let (min, latest) = p.version_bounds();
        out.open("if version is not None:");
        out.line(format!("pb_r.set_version(version, {}, {})", min, latest));
        out.pop();
    }
    out.open("try:");
    out.line("p = cls.decode_from(pb_r)");
    out.pop();
    out.open("except PbError as e:");
    out.open("if e.kind == PbError.INCOMPLETE:");
    out.line("return None, max((e.needed_bits + 7) // 8, 1)");
    out.pop();
    out.line("raise");
    out.pop();
    out.line("return p, (pb_r.position_bits() + 7) // 8");
    out.close("");
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Python>::new(p, Mode::Decode);
    out.line("@classmethod");
    out.open("def frame_len(cls, data) -> Optional[int]:");
    out.line(format!(
        "\"\"\"The packet's size from its first {} byte(s), or None until they are there.\"\"\"",
        f.header_bytes
    ));
    if f.header_bytes > 0 {
        out.open(format!("if len(data) < {}:", f.header_bytes));
        out.line("return None");
        out.pop();
    }
    out.line("p = cls()");
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            out.open(format!("if {}:", scope.expr(c)));
        }
        out.line("pb_r = PbReader(data)");
        out.line(format!("pb_r.skip_bits({})", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})", nbytes, Python::little(endian)),
            _ => format!("pb_r.read_bits({})", h.container_bits),
        };
        let bits = format!("(({} >> {}) & 0x{:x})", raw, h.shift, mask(h.bits));
        let v = if h.signed { format!("_pb_sext({}, {})", bits, h.bits) } else { bits };
        out.line(format!("p.{} = {}", ident(&m.name), v));
        if h.when.is_some() {
            out.pop();
        }
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.open(format!("if len(data) < {}:", scope.expr(need)));
            out.line("return None");
            out.pop();
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p.{} = {}", ident(&m.name), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("pb_n = {}", scope.expr(&f.total)));
    out.open("if pb_n < 0:");
    out.line("raise PbReader(data).error(PbError.INVALID, \"negative length %d\" % pb_n)");
    out.pop();
    out.line("return pb_n");
    out.close("");
}
