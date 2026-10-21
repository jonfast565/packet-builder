//! Stream helpers: `try_decode` (a packet, or how many more bytes are
//! needed) and `frame_len` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{Rust, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

/// `data_ty`: how `decode` takes its input (`&'a [u8]` for zero-copy values).
pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet, data_ty: &str) {
    if !p.params.is_empty() {
        return;
    }
    out.line("");
    out.line("/// Decode from a buffer that may end mid-packet (a stream): the packet and");
    out.line("/// the bytes it took, or how many more bytes are needed at least.");
    out.open(format!("pub fn try_decode(data: {}) -> Result<PbStatus<Self>, PbError> {{", data_ty));
    out.line("let mut pb_r = PbReader::new(data);");
    out.open("match Self::decode_from(&mut pb_r) {");
    out.line("Ok(p) => Ok(PbStatus::Done(p, pb_r.position_bits().div_ceil(8))),");
    out.line(
        "Err(e) if e.kind == PbErrorKind::Incomplete => Ok(PbStatus::Incomplete(e.needed_bits.div_ceil(8).max(1))),",
    );
    out.line("Err(e) => Err(e),");
    out.close("}");
    out.close("}");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line("");
        out.line("/// `try_decode` as protocol version `version`.");
        out.open(format!("pub fn try_decode_v(data: {}, version: u32) -> Result<PbStatus<Self>, PbError> {{", data_ty));
        out.line("let mut pb_r = PbReader::new(data);");
        out.line(format!("pb_r.set_version(version as i64, {}, {})?;", min, latest));
        out.open("match Self::decode_from(&mut pb_r) {");
        out.line("Ok(p) => Ok(PbStatus::Done(p, pb_r.position_bits().div_ceil(8))),");
        out.line(
            "Err(e) if e.kind == PbErrorKind::Incomplete => Ok(PbStatus::Incomplete(e.needed_bits.div_ceil(8).max(1))),",
        );
        out.line("Err(e) => Err(e),");
        out.close("}");
        out.close("}");
    }
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Rust>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "/// The size of the packet at the start of `data`, from its first {} byte(s); None until",
        f.header_bytes
    ));
    out.line("/// they are there.");
    out.open("pub fn frame_len(data: &[u8]) -> Result<Option<usize>, PbError> {");
    if f.header_bytes > 0 {
        out.line(format!("if data.len() < {} {{ return Ok(None); }}", f.header_bytes));
    }
    let uses_p = !f.fields.is_empty() || !f.calcs.is_empty();
    if uses_p {
        out.line("let mut p = Self::default();");
    }
    for h in &f.fields {
        let m = &p.members[h.member];
        out.open("{");
        out.line("let mut pb_r = PbReader::new(data);");
        out.line(format!("pb_r.skip_bits({})?;", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
            _ => format!("pb_r.read_bits({})?", h.container_bits),
        };
        out.line(format!("let pb_c: u64 = {};", raw));
        let bits = format!("((pb_c >> {}) & 0x{:x})", h.shift, mask(h.bits));
        let v = if h.signed { format!("pb_sext({}, {})", bits, h.bits) } else { bits };
        out.line(format!("p.{} = {} as {};", ident(&m.name), v, scalar_type(&m.ty)));
        out.close("}");
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p.{} = {};", ident(&m.name), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("let pb_n: i64 = {};", scope.expr(&f.total)));
    out.open("if pb_n < 0 {");
    out.line("return Err(PbReader::new(data).error(PbErrorKind::Invalid, format!(\"negative length {}\", pb_n)));");
    out.close("}");
    out.line("Ok(Some(pb_n as usize))");
    out.close("}");
}
