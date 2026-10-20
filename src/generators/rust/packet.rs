//! A Rust struct with `decode`/`encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{ident, member_type, scalar_type};
use crate::generators::common::union::variant_name;
use crate::generators::common::{Out, StepEmitter, magic_literal, member_category, param_var};
use crate::ir::{Arm, Packet, Union};

/// A Rust enum with one variant per arm.
pub fn emit_union(out: &mut Out, u: &Union) {
    out.line("#[derive(Debug, Clone, PartialEq)]");
    out.open(format!("pub enum {} {{", u.name));
    for arm in &u.arms {
        let values: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
        out.line(format!(
            "/// {}",
            if arm.default { "Any other selector value.".into() } else { format!("Selector {}.", values.join(", ")) }
        ));
        match arm_type(arm) {
            Some(t) => out.line(format!("{}({}),", variant_name(arm), t)),
            None => out.line(format!("{},", variant_name(arm))),
        }
    }
    out.close("}");
    out.line("");
    out.open(format!("impl Default for {} {{", u.name));
    out.open("fn default() -> Self {");
    let first = &u.arms[0];
    match arm_type(first) {
        Some(_) => out.line(format!("{}::{}(Default::default())", u.name, variant_name(first))),
        None => out.line(format!("{}::{}", u.name, variant_name(first))),
    }
    out.close("}");
    out.close("}");
    out.line("");
}

/// The Rust type an arm holds.
pub fn arm_type(arm: &Arm) -> Option<String> {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => None,
        (Some(_), true) => Some("Vec<u8>".into()),
        (Some(t), false) => Some(scalar_type(t)),
    }
}

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

    // Parameters: `, pbp_a: u8` in signatures, `, pbp_a` in calls.
    let decl: String = p.params.iter().map(|x| format!(", {}: {}", param_var(&x.name), scalar_type(&x.ty))).collect();
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();
    let touch = |out: &mut Out| {
        for x in &p.params {
            out.line(format!("let _ = {};", param_var(&x.name)));
        }
    };

    out.open(format!("impl {} {{", name));

    // decode
    out.line("/// Decode from the start of `data`. Trailing bytes are ignored.");
    out.open(format!("pub fn decode(data: &[u8]{}) -> Result<{}, PbError> {{", decl, name));
    out.line("let mut pb_r = PbReader::new(data);");
    out.line(format!("Self::decode_from(&mut pb_r{})", pass));
    out.close("}");
    out.line("");
    out.open(format!("pub fn decode_from(pb_r: &mut PbReader{}) -> Result<{}, PbError> {{", decl, name));
    touch(out);
    out.line(format!("pb_r.enter(\"{}\")?;", name));
    out.line(format!("let mut p = {}::default();", name));
    if p.needs_start(false) {
        out.line("let pb_start = pb_r.position_bits();");
    }
    Decoder::new(p).emit_steps(out);
    out.line("pb_r.leave();");
    out.line("Ok(p)");
    out.close("}");
    out.line("");

    // encode
    out.open(format!("pub fn encode(&self{}) -> Result<Vec<u8>, PbError> {{", decl));
    out.line("let mut pb_w = PbWriter::new();");
    out.line(format!("self.encode_to(&mut pb_w{})?;", pass));
    out.line("pb_w.finish()");
    out.close("}");
    out.line("");
    out.open(format!("pub fn encode_to(&self, pb_w: &mut PbWriter{}) -> Result<(), PbError> {{", decl));
    touch(out);
    out.line(format!("pb_w.enter(\"{}\")?;", name));
    out.line("let p = self;");
    if p.needs_start(true) {
        out.line("let pb_start = pb_w.position_bits();");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        encoder.define_local(out, m, e);
    }
    encoder.emit_steps(out);
    out.line("pb_w.leave();");
    out.line("Ok(())");
    out.close("}");

    out.close("}");
}
