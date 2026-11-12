//! Stream helpers: `try_decode` (a packet, or how many more bytes are
//! needed) and `frame_len` (a packet's size from its header).

use super::naming::Lua;
use crate::generators::common::lua::store_value;
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let versioned = p.versions.is_some();
    out.line("-- Decode from a buffer that may end mid-packet (a stream): the packet and the");
    out.line("-- bytes taken, or nil and n when at least n more bytes are needed.");
    out.open(format!("function C.try_decode(data{})", if versioned { ", version" } else { "" }));
    out.line("local r = pb_reader(data)");
    if versioned {
        let (min, latest) = p.version_bounds();
        out.line(format!("if version ~= nil then r:set_version(version, {}, {}) end", min, latest));
    }
    out.line("return pb_try(C.decode_from, r)");
    out.close("end");
    out.line("");
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Lua>::new(p, Mode::Decode);
    out.line(format!("-- The packet's size from its first {} byte(s), or nil until they are there.", f.header_bytes));
    out.open("function C.frame_len(data)");
    if f.header_bytes > 0 {
        out.line(format!("if #data < {} then return nil end", f.header_bytes));
    }
    out.line("local p = C.new()");
    out.line("local r");
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            out.open(format!("if {} then", scope.expr(c)));
        }
        out.line("r = pb_reader(data)");
        out.line(format!("r:skip_bits({})", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("r:read_uint({}, {})", nbytes, Lua::little(endian)),
            _ => format!("r:read_bits({})", h.container_bits),
        };
        let bits = format!("(({} >> {}) & 0x{:x})", raw, h.shift, mask(h.bits));
        let v = if h.signed { format!("pb_sext({}, {})", bits, h.bits) } else { bits };
        out.line(format!("{} = {}", scope.field(m), v));
        if h.when.is_some() {
            out.close("end");
        }
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.line(format!("if #data < {} then return nil end", scope.expr(need)));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("{} = {}", scope.field(m), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("local pb_n = {}", scope.expr(&f.total)));
    out.line("if pb_n < 0 then pb_reader(data):fail(\"invalid\", \"negative length \" .. pb_n) end");
    out.line("return pb_n");
    out.close("end");
    out.line("");
}
