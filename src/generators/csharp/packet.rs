//! A sealed C# class with `Decode`/`Encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{default_value, member_type, prop_name, scalar_type};
use crate::generators::common::union::variant_name;
use crate::generators::common::{Out, StepEmitter, member_category};
use crate::ir::{Packet, Union, ValueType};

/// A union as an abstract class with one sealed subclass per arm; arms with
/// a value hold it in `Value`. Packet types are spelled with the namespace,
/// since an arm's class may share a packet's name.
pub fn emit_union(out: &mut Out, u: &Union, ns: &str) {
    out.line("/// <summary>One arm of a union: the subclass says which.</summary>");
    out.line(format!("public abstract class {}", u.name));
    out.open("{");
    out.line(format!("public static {} PbDefault() => new {}();", u.name, variant_name(&u.arms[0])));
    for arm in &u.arms {
        out.line("");
        let doc = if arm.default {
            "Any other selector value.".to_string()
        } else {
            let v: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            format!("Selector {}.", v.join(", "))
        };
        out.line(format!("/// <summary>{}</summary>", doc));
        let v = variant_name(arm);
        match (&arm.ty, arm.is_bytes()) {
            (None, _) => out.line(format!("public sealed class {} : {} {{ }}", v, u.name)),
            (Some(_), true) => out.line(format!(
                "public sealed class {} : {} {{ public byte[] Value {{ get; set; }} = Array.Empty<byte>(); }}",
                v, u.name
            )),
            (Some(ValueType::Packet(n)), false) => out.line(format!(
                "public sealed class {} : {} {{ public global::{}.{} Value {{ get; set; }} = new global::{}.{}(); }}",
                v, u.name, ns, n, ns, n
            )),
            (Some(t), false) => out.line(format!(
                "public sealed class {} : {} {{ public {} Value {{ get; set; }} }}",
                v,
                u.name,
                scalar_type(t)
            )),
        }
    }
    out.close("}");
}

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
    out.line(format!("pbR.Enter(\"{}\");", name));
    out.line(format!("var p = new {}();", name));
    if p.needs_start(false) {
        out.line("long pb_start = pbR.PositionBits;");
    }
    Decoder::new(p).emit_steps(out);
    out.line("pbR.Leave();");
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
    out.line(format!("pbW.Enter(\"{}\");", name));
    out.line("var p = this;");
    if p.needs_start(true) {
        out.line("long pb_start = pbW.PositionBits;");
    }
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        encoder.define_local(out, m, e);
    }
    encoder.emit_steps(out);
    out.line("pbW.Leave();");
    out.close("}");
    out.close("}");
}
