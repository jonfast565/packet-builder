//! A Go struct with `Decode<Name>`/`Encode` functions for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{field_name, gofmt_widths, member_type, scalar_type};
use crate::generators::common::union::variant_name;
use crate::generators::common::{Out, StepEmitter, magic_literal, member_category, param_var};
use crate::ir::{Arm, Module, Packet, Union, ValueType};

/// The Go name of an arm's kind constant (`MessageBodyText`).
pub fn arm_kind(u: &str, arm: &Arm) -> String {
    format!("{}{}", u, variant_name(arm))
}

/// The Go type of an arm's field: packets by pointer, bytes as a slice.
fn arm_type(arm: &Arm) -> Option<String> {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => None,
        (Some(_), true) => Some("[]byte".into()),
        (Some(ValueType::Packet(n)), false) => Some(format!("*{}", n)),
        (Some(t), false) => Some(scalar_type(t)),
    }
}

/// A union as a struct: `Kind` says which arm's field holds the value.
pub fn emit_union(out: &mut Out, u: &Union) {
    let kind = format!("{}Kind", u.name);
    out.line(format!("// {} says which arm of a {} is in use.", kind, u.name));
    out.line(format!("type {} int", kind));
    out.line("");
    out.line("const (");
    out.push();
    for (i, arm) in u.arms.iter().enumerate() {
        if i == 0 {
            out.line(format!("{} {} = iota", arm_kind(&u.name, arm), kind));
        } else {
            out.line(arm_kind(&u.name, arm));
        }
    }
    out.pop();
    out.line(")");
    out.line("");
    out.line(format!("// {} holds one of its arms; Kind says which.", u.name));
    out.open(format!("type {} struct {{", u.name));
    let fields: Vec<(String, String)> = std::iter::once(("Kind".to_string(), kind.clone()))
        .chain(u.arms.iter().filter_map(|a| arm_type(a).map(|t| (variant_name(a), t))))
        .collect();
    let names: Vec<String> = fields.iter().map(|(n, _)| n.clone()).collect();
    let widths = gofmt_widths(&names, &vec![false; names.len()]);
    for ((name, ty), width) in fields.iter().zip(widths) {
        out.line(format!("{:<w$} {}", name, ty, w = width));
    }
    out.close("}");
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
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

    // Parameters: `, pbp_a uint8` in signatures, `, pbp_a` in calls.
    let decl: String = p.params.iter().map(|x| format!(", {} {}", param_var(&x.name), scalar_type(&x.ty))).collect();
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();

    out.line(format!("// Decode{} decodes a {} from the start of data. Trailing bytes are ignored.", name, name));
    out.open(format!("func Decode{}(data []byte{}) (*{}, error) {{", name, decl, name));
    out.line("pbR := NewPbReader(data)");
    out.line(format!("p := pbDecode{}(pbR{})", name, pass));
    out.open("if err := pbR.Err(); err != nil {");
    out.line("return nil, err");
    out.close("}");
    out.line("return &p, nil");
    out.close("}");
    out.line("");
    let versions = p.versions.map(|_| p.version_bounds());
    if let Some((min, latest)) = versions {
        out.line(format!("// Decode{}V decodes a {} as protocol version version ({}..{}).", name, name, min, latest));
        out.open(format!("func Decode{}V(data []byte, version int{}) (*{}, error) {{", name, decl, name));
        out.line("pbR := NewPbReader(data)");
        out.line(format!("pbR.SetVersion(int64(version), {}, {})", min, latest));
        out.open("if err := pbR.Err(); err != nil {");
        out.line("return nil, err");
        out.close("}");
        out.line(format!("p := pbDecode{}(pbR{})", name, pass));
        out.open("if err := pbR.Err(); err != nil {");
        out.line("return nil, err");
        out.close("}");
        out.line("return &p, nil");
        out.close("}");
        out.line("");
    }

    out.line(format!("// DecodeFrom reads a {} from pbR, which keeps its position.", name));
    out.open(format!("func (p *{}) DecodeFrom(pbR *PbReader{}) error {{", name, decl));
    out.line(format!("*p = pbDecode{}(pbR{})", name, pass));
    out.line("return pbR.Err()");
    out.close("}");
    out.line("");

    out.open(format!("func pbDecode{}(pbR *PbReader{}) (p {}) {{", name, decl, name));
    out.line(format!("pbR.Enter(\"{}\")", name));
    if p.needs_start(false) {
        out.line("pb_start := pbR.PositionBits()");
    }
    Decoder::new(p, zero_copy).emit_steps(out);
    out.line("pbR.Leave()");
    out.line("return p");
    out.close("}");
    out.line("");

    out.open(format!("func (p *{}) Encode({}) ([]byte, error) {{", name, decl.trim_start_matches(", ")));
    out.line("pbW := NewPbWriter()");
    out.open(format!("if err := p.EncodeTo(pbW{}); err != nil {{", pass));
    out.line("return nil, err");
    out.close("}");
    out.line("return pbW.Finish()");
    out.close("}");
    out.line("");
    if let Some((min, latest)) = versions {
        out.line(format!("// EncodeV encodes as protocol version version ({}..{}).", min, latest));
        out.open(format!("func (p *{}) EncodeV(version int{}) ([]byte, error) {{", name, decl));
        out.line("pbW := NewPbWriter()");
        out.line(format!("pbW.SetVersion(int64(version), {}, {})", min, latest));
        out.open(format!("if err := p.EncodeTo(pbW{}); err != nil {{", pass));
        out.line("return nil, err");
        out.close("}");
        out.line("return pbW.Finish()");
        out.close("}");
        out.line("");
    }

    out.open(format!("func (p *{}) EncodeTo(pbW *PbWriter{}) error {{", name, decl));
    out.line(format!("pbW.Enter(\"{}\")", name));
    if p.needs_start(true) {
        out.line("pb_start := pbW.PositionBits()");
    }
    let encoder = Encoder::new(p);
    encoder.emit_locals(out);
    encoder.emit_steps(out);
    out.line("pbW.Leave()");
    out.line("return pbW.Err()");
    out.close("}");
    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
}
