//! Stream helpers: `<P>_try_decode` (a packet, or how many more bytes are
//! needed) and `<P>_frame_len` (a packet's size from its header).

use super::decode::bits_value;
use super::expr::store_value;
use super::locals::{Locals, body};
use super::naming::{Fortran, type_name};
use crate::generators::common::{Dialect, Mode, Out, Scope};
use crate::ir::{Codec, Module, Packet};

/// `if (present(pb_version)) ...`: adopt the caller's version on `stream`.
pub fn set_version(out: &mut Out, p: &Packet, stream: &str) {
    if p.versions.is_none() {
        return;
    }
    let (min, latest) = p.version_bounds();
    out.open("if (present(pb_version)) then");
    out.line(format!(
        "if (pb_version /= 0) call pb_set_version({}, int(pb_version, int64), {}, {})",
        stream, min, latest
    ));
    out.close("end if");
}

pub fn streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let t = type_name(&p.name);
    let ver = if p.versions.is_some() { ", pb_version" } else { "" };
    out.line("");
    out.line("!> Decode from a buffer that may end mid-packet (a stream). On success PB_N is the");
    out.line("!> number of bytes taken; when PB_ERR%kind is PB_INCOMPLETE, the bytes still needed.");
    out.line(format!("subroutine {}_try_decode(pb_data, pbv, pb_n, pb_err{})", t, ver));
    let locals = Locals::default();
    locals.var("pb_data(:)", "integer(int8), intent(in)");
    locals.var("pbv", &format!("type({}), intent(out)", t));
    locals.var("pb_n", "integer(int64), intent(out)");
    locals.var("pb_err", "type(pb_error), intent(out)");
    if p.versions.is_some() {
        locals.var("pb_version", "integer, intent(in), optional");
    }
    locals.var("pb_r", "type(pb_reader)");
    let mut b = body();
    b.line("pb_n = 0");
    b.line("call pb_reader_init(pb_r, pb_data)");
    set_version(&mut b, p, "pb_r");
    b.line(format!("if (pb_r%e%kind == PB_OK) call {}_decode_from(pbv, pb_r)", t));
    b.line("pb_err = pb_r%e");
    b.open("if (pb_err%kind == PB_OK) then");
    b.line("pb_n = (pb_r%pos + 7) / 8");
    b.close("else if (pb_err%kind == PB_INCOMPLETE) then");
    b.push();
    b.line("pb_n = max((pb_err%needed_bits + 7) / 8, 1_int64)");
    b.close("end if");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_try_decode", t));

    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Fortran>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "!> The packet's size from its first {} byte(s); PB_ERR%kind is PB_INCOMPLETE until they are there.",
        f.header_bytes
    ));
    out.line(format!("subroutine {}_frame_len(pb_data, pb_n, pb_err)", t));
    let locals = Locals::default();
    locals.var("pb_data(:)", "integer(int8), intent(in)");
    locals.var("pb_n", "integer(int64), intent(out)");
    locals.var("pb_err", "type(pb_error), intent(out)");
    if !f.fields.is_empty() || !f.calcs.is_empty() {
        locals.var("pbv", &format!("type({})", t));
    }
    locals.var("pb_r", "type(pb_reader)");
    if !f.fields.is_empty() {
        locals.var("pbc", "integer(int64)");
    }
    let mut b = body();
    b.line("pb_n = 0");
    b.line("call pb_reader_init(pb_r, pb_data)");
    let short = |b: &mut Out, need: String| {
        b.open(format!("if (size(pb_data, kind=int64) < {}) then", need));
        b.line("call pb_fail(pb_r, PB_INCOMPLETE, 'the header is incomplete')");
        b.line("pb_err = pb_r%e");
        b.line("return");
        b.close("end if");
    };
    if f.header_bytes > 0 {
        short(&mut b, format!("{}_int64", f.header_bytes));
    }
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            b.open(format!("if ({}) then", scope.expr(c)));
        }
        b.line("call pb_reader_init(pb_r, pb_data)");
        b.line(format!("call pb_skip_bits(pb_r, {}_int64)", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pb_read_uint(pb_r, {}, {})", nbytes, Fortran::little(endian)),
            _ => format!("pb_read_bits(pb_r, {})", h.container_bits),
        };
        b.line(format!("pbc = {}", raw));
        b.line(format!("{} = {}", scope.field(m), bits_value(&m.ty, "pbc", h.shift, h.bits, h.signed)));
        if h.when.is_some() {
            b.close("end if");
        }
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            short(&mut b, scope.expr(need));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            b.line(format!("{} = {}", scope.field(m), store_value(scope.expr(e), &m.ty)));
        }
    }
    b.line(format!("pb_n = {}", scope.expr(&f.total)));
    b.open("if (pb_n < 0) then");
    b.line("call pb_fail(pb_r, PB_INVALID, 'negative length ' // pb_itoa(pb_n))");
    b.line("pb_n = 0");
    b.close("end if");
    b.line("pb_err = pb_r%e");
    locals.routine(out, b);
    out.line(format!("end subroutine {}_frame_len", t));
}
