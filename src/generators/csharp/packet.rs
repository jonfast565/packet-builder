//! A sealed C# class with `Decode`/`Encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::expr::store_value;
use super::naming::{default_value, member_type, prop_name, scalar_type};
use crate::generators::common::{Out, StepEmitter, member_category};
use crate::ir::Packet;

pub fn emit_packet(out: &mut Out, p: &Packet) {
    let name = &p.name;
    out.line(format!("public sealed class {}", name));
    out.open("{");
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/// <summary>Values from <see cref=\"{}\"/>.</summary>", cat));
        }
        let decl = format!("public {} {} {{ get; set; }}", member_type(m), prop_name(name, &m.name));
        match default_value(m) {
            Some(d) => out.line(format!("{} = {};", decl, d)),
            None => out.line(decl),
        }
    }
    out.line("");
    out.line("/// <summary>Decode from the start of <paramref name=\"data\"/>. Trailing bytes are ignored.</summary>");
    out.line(format!("public static {} Decode(byte[] data) => DecodeFrom(new PbReader(data));", name));
    out.line("");
    out.line(format!("public static {} DecodeFrom(PbReader pbR)", name));
    out.open("{");
    out.line(format!("var p = new {}();", name));
    if p.uses_align() {
        out.line("long pbStart = pbR.PositionBits;");
    }
    Decoder::new(p).emit_steps(out);
    out.line("return p;");
    out.close("}");
    out.line("");
    out.line("public byte[] Encode()");
    out.open("{");
    out.line("var pbW = new PbWriter();");
    out.line("EncodeTo(pbW);");
    out.line("return pbW.ToArray();");
    out.close("}");
    out.line("");
    out.line("public void EncodeTo(PbWriter pbW)");
    out.open("{");
    out.line("var p = this;");
    if p.uses_align() {
        out.line("long pbStart = pbW.PositionBits;");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        out.line(format!("{} pbc_{} = {};", scalar_type(&m.ty), m.name, store_value(encoder.scope.expr(e), &m.ty)));
    }
    encoder.emit_steps(out);
    out.close("}");
    out.close("}");
}
