//! A Go struct with `Decode<Name>`/`Encode` functions for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::expr::store_value;
use super::naming::{field_name, member_type};
use crate::generators::common::{Out, StepEmitter};
use crate::ir::Packet;

pub fn emit_packet(out: &mut Out, p: &Packet) {
    let name = &p.name;
    out.open(format!("type {} struct {{", name));
    // gofmt alignment
    let width = p.members.iter().map(|m| field_name(&m.name).len()).max().unwrap_or(0);
    for m in &p.members {
        out.line(format!("{:<w$} {}", field_name(&m.name), member_type(m), w = width));
    }
    out.close("}");
    out.line("");

    out.line(format!("// Decode{} decodes a {} from the start of data. Trailing bytes are ignored.", name, name));
    out.open(format!("func Decode{}(data []byte) (*{}, error) {{", name, name));
    out.line("pbR := NewPbReader(data)");
    out.line(format!("p := pbDecode{}(pbR)", name));
    out.open("if err := pbR.Err(); err != nil {");
    out.line("return nil, err");
    out.close("}");
    out.line("return &p, nil");
    out.close("}");
    out.line("");

    out.line(format!("// DecodeFrom reads a {} from pbR, which keeps its position.", name));
    out.open(format!("func (p *{}) DecodeFrom(pbR *PbReader) error {{", name));
    out.line(format!("*p = pbDecode{}(pbR)", name));
    out.line("return pbR.Err()");
    out.close("}");
    out.line("");

    out.open(format!("func pbDecode{}(pbR *PbReader) (p {}) {{", name, name));
    if p.uses_align() {
        out.line("pbStart := pbR.PositionBits()");
    }
    Decoder::new(p).emit_steps(out);
    out.line("return p");
    out.close("}");
    out.line("");

    out.open(format!("func (p *{}) Encode() ([]byte, error) {{", name));
    out.line("pbW := NewPbWriter()");
    out.open("if err := p.EncodeTo(pbW); err != nil {");
    out.line("return nil, err");
    out.close("}");
    out.line("return pbW.Bytes(), nil");
    out.close("}");
    out.line("");

    out.open(format!("func (p *{}) EncodeTo(pbW *PbWriter) error {{", name));
    if p.uses_align() {
        out.line("pbStart := pbW.PositionBits()");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        out.line(format!("pbc_{} := {}", m.name, store_value(e, encoder.scope.expr(e), &m.ty)));
    }
    encoder.emit_steps(out);
    out.line("return pbW.Err()");
    out.close("}");
}
