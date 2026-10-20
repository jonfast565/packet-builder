//! A Rust struct with `decode`/`encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::expr::store_value;
use super::naming::{ident, member_type, scalar_type};
use crate::generators::common::{Out, StepEmitter, magic_literal, member_category};
use crate::ir::Packet;

pub fn emit_packet(out: &mut Out, p: &Packet) {
    let name = &p.name;

    let magic = p.members.iter().any(|m| m.magic().is_some());
    out.line(if magic { "#[derive(Debug, Clone, PartialEq)]" } else { "#[derive(Debug, Clone, PartialEq, Default)]" });
    out.open(format!("pub struct {} {{", name));
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/// Values from [`{}`].", ident(cat)));
        }
        out.line(format!("pub {}: {},", ident(&m.name), member_type(m)));
    }
    out.close("}");
    out.line("");

    if magic {
        // Members with `== value` start with that value.
        out.open(format!("impl Default for {} {{", name));
        out.open("fn default() -> Self {");
        out.open(format!("{} {{", name));
        for m in &p.members {
            let v = magic_literal(m).unwrap_or_else(|| "Default::default()".into());
            out.line(format!("{}: {},", ident(&m.name), v));
        }
        out.close("}");
        out.close("}");
        out.close("}");
        out.line("");
    }

    out.open(format!("impl {} {{", name));

    // decode
    out.line("/// Decode from the start of `data`. Trailing bytes are ignored.");
    out.open(format!("pub fn decode(data: &[u8]) -> Result<{}, PbError> {{", name));
    out.line("let mut pb_r = PbReader::new(data);");
    out.line("Self::decode_from(&mut pb_r)");
    out.close("}");
    out.line("");
    out.open(format!("pub fn decode_from(pb_r: &mut PbReader) -> Result<{}, PbError> {{", name));
    out.line(format!("pb_r.enter(\"{}\")?;", name));
    out.line(format!("let mut p = {}::default();", name));
    if p.uses_align() {
        out.line("let pb_start = pb_r.position_bits();");
    }
    Decoder::new(p).emit_steps(out);
    out.line("pb_r.leave();");
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
    out.line(format!("pb_w.enter(\"{}\")?;", name));
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
    out.line("pb_w.leave();");
    out.line("Ok(())");
    out.close("}");

    out.close("}");
}
