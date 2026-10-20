//! Stream helpers: `P_try_decode` (a packet, or how many more bytes are
//! needed) and `P_frame_len` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{C, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

pub fn declare_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = &p.name;
    out.line("/* Decode from a buffer that may end mid-packet (a stream): PB_OK with *used set to");
    out.line(" * the bytes taken, or PB_ERR_INCOMPLETE with *used set to how many more bytes are");
    out.line(" * needed at least. */");
    out.line(format!("int {}_try_decode({} *p, const uint8_t *data, size_t len, size_t *used);", name, name));
    if let Some(f) = module.frame_length(p) {
        out.line(format!(
            "/* The packet's size from its first {} byte(s): PB_OK with *size, or PB_ERR_INCOMPLETE",
            f.header_bytes
        ));
        out.line(" * until they are there. */");
        out.line(format!("int {}_frame_len(const uint8_t *data, size_t len, size_t *size);", name));
    }
}

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = &p.name;
    out.line("");
    out.open(format!("int {}_try_decode({} *p, const uint8_t *data, size_t len, size_t *used) {{", name, name));
    out.line("pb_reader pb_r;");
    out.line("int rc;");
    out.line("pb_reader_init(&pb_r, data, len);");
    out.line(format!("rc = {}_decode_from(p, &pb_r);", name));
    out.line("if (rc == PB_OK) *used = (pb_r.pos + 7) / 8;");
    out.line("else if (rc == PB_ERR_INCOMPLETE) *used = pb_r.err.needed_bits ? (pb_r.err.needed_bits + 7) / 8 : 1;");
    out.line("return rc;");
    out.close("}");
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<C>::new(p, Mode::Decode);
    out.line("");
    out.open(format!("int {}_frame_len(const uint8_t *data, size_t len, size_t *size) {{", name));
    out.line(format!("{} pb_value;", name));
    out.line(format!("{} *p = &pb_value;", name));
    out.line("uint64_t pb_c = 0;");
    out.line("int64_t pb_n;");
    out.line("(void)data;");
    if f.header_bytes > 0 {
        out.line(format!("if (len < {}) return PB_ERR_INCOMPLETE;", f.header_bytes));
    } else {
        out.line("(void)len;");
    }
    out.line("memset(p, 0, sizeof *p);");
    out.line("(void)p;");
    out.line("(void)pb_c;");
    for h in &f.fields {
        let m = &p.members[h.member];
        out.open("{");
        out.line("pb_reader pb_r;");
        out.line("pb_reader_init(&pb_r, data, len);");
        out.line(format!("PB_PASS(pb_skip_bits(&pb_r, {}));", h.offset_bits));
        match &h.container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("PB_PASS(pb_read_uint(&pb_r, {}, {}, &pb_c));", nbytes, C::little(endian)))
            }
            _ => out.line(format!("PB_PASS(pb_read_bits(&pb_r, {}, &pb_c));", h.container_bits)),
        }
        let bits = format!("((pb_c >> {}) & UINT64_C(0x{:x}))", h.shift, mask(h.bits));
        let v = if h.signed { format!("pb_sext({}, {})", bits, h.bits) } else { bits };
        out.line(format!("p->{} = ({}){};", ident(&m.name), scalar_type(&m.ty), v));
        out.close("}");
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p->{} = {};", ident(&m.name), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("pb_n = {};", scope.expr(&f.total)));
    out.line("if (pb_n < 0) return PB_ERR_INVALID;");
    out.line("*size = (size_t)pb_n;");
    out.line("return PB_OK;");
    out.close("}");
}
