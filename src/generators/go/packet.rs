//! A Go struct with `Decode<Name>`/`Encode` functions for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{field_name, gofmt_widths, member_type};
use crate::generators::common::{Out, StepEmitter, magic_literal, member_category};
use crate::ir::{Packet, ValueType};

pub fn emit_packet(out: &mut Out, p: &Packet) {
    let name = &p.name;
    out.open(format!("type {} struct {{", name));
    let names: Vec<_> = p.members.iter().map(|m| field_name(&m.name)).collect();
    let commented: Vec<_> = p.members.iter().map(|m| member_category(m).is_some()).collect();
    let widths = gofmt_widths(&names, &commented);
    for ((m, name), width) in p.members.iter().zip(&names).zip(widths) {
        if let Some(cat) = member_category(m) {
            out.line(format!("// Values: {}*", cat));
        }
        out.line(format!("{:<w$} {}", name, member_type(m), w = width));
    }
    out.close("}");
    out.line("");

    out.line(format!("// New{} returns a {} whose members declared `== value` hold that value.", name, name));
    out.open(format!("func New{}() *{} {{", name, name));
    out.line(format!("p := &{}{{}}", name));
    for m in &p.members {
        match (&m.array, &m.ty, magic_literal(m)) {
            (None, ValueType::Packet(n), _) => out.line(format!("p.{} = *New{}()", field_name(&m.name), n)),
            (None, _, Some(v)) => out.line(format!("p.{} = {}", field_name(&m.name), v)),
            _ => {}
        }
    }
    out.line("return p");
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
    out.line(format!("pbR.Enter(\"{}\")", name));
    if p.needs_start(false) {
        out.line("pb_start := pbR.PositionBits()");
    }
    Decoder::new(p).emit_steps(out);
    out.line("pbR.Leave()");
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
    out.line(format!("pbW.Enter(\"{}\")", name));
    if p.needs_start(true) {
        out.line("pb_start := pbW.PositionBits()");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        encoder.define_local(out, m, e);
    }
    encoder.emit_steps(out);
    out.line("pbW.Leave()");
    out.line("return pbW.Err()");
    out.close("}");
}
