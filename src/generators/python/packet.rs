//! A Python dataclass with `decode`/`encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{annotation, ident};
use crate::generators::common::{Out, StepEmitter, member_category, param_var};
use crate::ir::{Arm, Module, Packet, Union, ValueType};

/// The value an arm starts with.
fn arm_default(arm: &Arm) -> String {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => "None".into(),
        (Some(_), true) => "b\"\"".into(),
        (Some(ValueType::Packet(n)), false) => format!("{}()", n),
        (Some(_), false) => "0".into(),
    }
}

/// A union as a dataclass: `kind` names the arm and `value` holds its value.
pub fn emit_union(out: &mut Out, u: &Union) {
    out.line("@dataclass");
    out.open(format!("class {}:", u.name));
    let arms: Vec<String> = u.arms.iter().map(|a| a.name.clone()).collect();
    out.line(format!(
        "\"\"\"One arm of a union: `kind` is one of {}; `value` is the arm's value.\"\"\"",
        arms.join(", ")
    ));
    out.line("");
    out.line(format!("kind: str = \"{}\"", u.arms[0].name));
    out.line("value: object = None");
    out.line("");
    out.line("@staticmethod");
    out.open(format!("def pb_default() -> \"{}\":", u.name));
    out.line(format!("return {}(\"{}\", {})", u.name, u.arms[0].name, arm_default(&u.arms[0])));
    out.close("");
    super::json::emit_union_json(out, u);
    out.pop();
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
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
    // Parameters: `, pbp_a` in signatures and calls.
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();
    // Files with versions: an optional protocol version to code as.
    let versions = p.versions.map(|_| p.version_bounds());
    out.line("@classmethod");
    if let Some((min, latest)) = versions {
        out.open(format!("def decode(cls, data{}, version=None) -> \"{}\":", pass, p.name));
        out.line(format!(
            "\"\"\"Decode from the start of `data` as protocol `version` ({}..{}; default: the",
            min, latest
        ));
        out.line("version in the data, or the latest). Trailing bytes are ignored.\"\"\"");
        out.line("pb_r = PbReader(data)");
        out.open("if version is not None:");
        out.line(format!("pb_r.set_version(version, {}, {})", min, latest));
        out.pop();
        out.line(format!("return cls.decode_from(pb_r{})", pass));
    } else {
        out.open(format!("def decode(cls, data{}) -> \"{}\":", pass, p.name));
        out.line("\"\"\"Decode from the start of `data`. Trailing bytes are ignored.\"\"\"");
        out.line(format!("return cls.decode_from(PbReader(data){})", pass));
    }
    out.close("");
    out.line("@classmethod");
    out.open(format!("def decode_from(cls, pb_r{}) -> \"{}\":", pass, p.name));
    out.line(format!("pb_r.enter(\"{}\")", p.name));
    out.line("p = cls()");
    if p.needs_start(false) {
        out.line("pb_start = pb_r.position_bits()");
    }
    Decoder::new(p, zero_copy).emit_steps(out);
    out.line("pb_r.leave()");
    out.line("return p");
    out.close("");

    if let Some((min, latest)) = versions {
        out.open(format!("def encode(self{}, version=None) -> bytes:", pass));
        out.line("pb_w = PbWriter()");
        out.open("if version is not None:");
        out.line(format!("pb_w.set_version(version, {}, {})", min, latest));
        out.pop();
    } else {
        out.open(format!("def encode(self{}) -> bytes:", pass));
        out.line("pb_w = PbWriter()");
    }
    out.line(format!("self.encode_to(pb_w{})", pass));
    out.line("return pb_w.finish()");
    out.close("");
    out.open(format!("def encode_to(self, pb_w{}) -> None:", pass));
    out.line(format!("pb_w.enter(\"{}\")", p.name));
    out.line("p = self");
    if p.needs_start(true) {
        out.line("pb_start = pb_w.position_bits()");
    }
    let encoder = Encoder::new(p);
    encoder.emit_locals(out);
    encoder.emit_steps(out);
    out.line("pb_w.leave()");
    out.close("");
    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
    out.pop();
}
