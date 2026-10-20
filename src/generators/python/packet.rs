//! A Python dataclass with `decode`/`encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::expr::store_value;
use super::naming::{annotation, ident};
use crate::generators::common::{Out, StepEmitter, member_category};
use crate::ir::Packet;

pub fn emit_packet(out: &mut Out, p: &Packet) {
    out.line("@dataclass");
    out.open(format!("class {}:", p.name));
    if p.members.is_empty() {
        out.line("pass");
    }
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("# values: {}", cat));
        }
        out.line(format!("{}: {}", ident(&m.name), annotation(m)));
    }
    out.line("");
    out.line("@classmethod");
    out.open(format!("def decode(cls, data) -> \"{}\":", p.name));
    out.line("\"\"\"Decode from the start of `data`. Trailing bytes are ignored.\"\"\"");
    out.line("return cls.decode_from(PbReader(data))");
    out.close("");
    out.line("@classmethod");
    out.open(format!("def decode_from(cls, pb_r) -> \"{}\":", p.name));
    out.line(format!("pb_r.enter(\"{}\")", p.name));
    out.line("p = cls()");
    if p.uses_align() {
        out.line("pb_start = pb_r.position_bits()");
    }
    Decoder::new(p).emit_steps(out);
    out.line("pb_r.leave()");
    out.line("return p");
    out.close("");

    out.open("def encode(self) -> bytes:");
    out.line("pb_w = PbWriter()");
    out.line("self.encode_to(pb_w)");
    out.line("return pb_w.finish()");
    out.close("");
    out.open("def encode_to(self, pb_w) -> None:");
    out.line(format!("pb_w.enter(\"{}\")", p.name));
    out.line("p = self");
    if p.uses_align() {
        out.line("pb_start = pb_w.position_bits()");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        out.line(format!("pbc_{} = {}", m.name, store_value(encoder.scope.expr(e), &m.ty)));
    }
    encoder.emit_steps(out);
    out.line("pb_w.leave()");
    out.close("");
    out.pop();
}
