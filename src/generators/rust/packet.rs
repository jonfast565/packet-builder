//! A Rust struct with `decode`/`encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::expr::store_value;
use super::naming::{ident, member_type, scalar_type};
use crate::generators::common::{Out, StepEmitter};
use crate::ir::Packet;

pub fn emit_packet(out: &mut Out, p: &Packet) {
    let name = &p.name;

    out.line("#[derive(Debug, Clone, PartialEq, Default)]");
    out.open(format!("pub struct {} {{", name));
    for m in &p.members {
        out.line(format!("pub {}: {},", ident(&m.name), member_type(m)));
    }
    out.close("}");
    out.line("");

    out.open(format!("impl {} {{", name));

    // decode
    out.line("/// Decode from the start of `data`. Trailing bytes are ignored.");
    out.open(format!("pub fn decode(data: &[u8]) -> Result<{}, PbError> {{", name));
    out.line("let mut pb_r = PbReader::new(data);");
    out.line("Self::decode_from(&mut pb_r)");
    out.close("}");
    out.line("");
    out.open(format!("pub fn decode_from(pb_r: &mut PbReader) -> Result<{}, PbError> {{", name));
    out.line(format!("let mut p = {}::default();", name));
    if p.uses_align() {
        out.line("let pb_start = pb_r.position_bits();");
    }
    Decoder::new(p).emit_steps(out);
    out.line("Ok(p)");
    out.close("}");
    out.line("");

    // encode
    out.open("pub fn encode(&self) -> Result<Vec<u8>, PbError> {");
    out.line("let mut pb_w = PbWriter::new();");
    out.line("self.encode_to(&mut pb_w)?;");
    out.line("Ok(pb_w.finish())");
    out.close("}");
    out.line("");
    out.open("pub fn encode_to(&self, pb_w: &mut PbWriter) -> Result<(), PbError> {");
    out.line("let p = self;");
    if p.uses_align() {
        out.line("let pb_start = pb_w.position_bits();");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        out.line(format!(
            "let pbc_{}: {} = {};",
            m.name,
            scalar_type(&m.ty),
            store_value(encoder.scope.expr(e), &m.ty)
        ));
    }
    encoder.emit_steps(out);
    out.line("Ok(())");
    out.close("}");

    out.close("}");
}
