//! A nested Java class with `decode`/`encode` methods for one packet, and
//! the class hierarchy of a union.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{arm_class, bytes_type, class_name, default_value, field_name, member_type, scalar_type};
use crate::generators::common::{Out, StepEmitter, member_category, param_var};
use crate::ir::{Module, Packet, Union, ValueType};

/// A union as an abstract class with one final subclass per arm; arms with
/// a value hold it in `value`. Packet types are qualified with the outer
/// class, since an arm's class may share a packet's name.
pub fn emit_union(out: &mut Out, u: &Union, outer: &str, zero_copy: bool) {
    let name = class_name(&u.name);
    out.line("/** One arm of a union: the subclass says which. */");
    out.open(format!("public abstract static class {} {{", name));
    out.line(format!("public static {} pbDefault() {{", name));
    out.line(format!("    return new {}();", arm_class(&u.name, &u.arms[0], outer)));
    out.line("}");
    for arm in &u.arms {
        out.line("");
        let doc = if arm.default {
            "Any other selector value.".to_string()
        } else {
            let v: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            format!("Selector {}.", v.join(", "))
        };
        out.line(format!("/** {} */", doc));
        let v = arm_class(&u.name, arm, outer);
        let (ty, default) = match (&arm.ty, arm.is_bytes()) {
            (None, _) => {
                out.line(format!("public static final class {} extends {} {{}}", v, name));
                continue;
            }
            (Some(_), true) => (
                bytes_type(zero_copy).to_string(),
                if zero_copy { "java.nio.ByteBuffer.allocate(0)".to_string() } else { "new byte[0]".to_string() },
            ),
            (Some(ValueType::Packet(n)), false) => {
                let t = format!("{}.{}", outer, class_name(n));
                (t.clone(), format!("new {}()", t))
            }
            (Some(t), false) => (scalar_type(t), String::new()),
        };
        out.open(format!("public static final class {} extends {} {{", v, name));
        if default.is_empty() {
            out.line(format!("public {} value;", ty));
        } else {
            out.line(format!("public {} value = {};", ty, default));
        }
        out.line("");
        out.line(format!("public {}() {{}}", v));
        out.line("");
        out.line(format!("public {}({} value) {{", v, ty));
        out.line("    this.value = value;");
        out.line("}");
        out.close("}");
    }
    super::json::emit_union_json(out, u, outer);
    out.close("}");
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool, outer: &str) {
    let name = class_name(&p.name);
    out.open(format!("public static final class {} {{", name));
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/** Values from {{@link {}}}. */", class_name(cat)));
        }
        let decl = format!("public {} {}", member_type(m, zero_copy), field_name(&m.name));
        match default_value(m, zero_copy) {
            Some(d) => out.line(format!("{} = {};", decl, d)),
            None => out.line(format!("{};", decl)),
        }
    }
    // Parameters: `, int pbp_a` in signatures, `, pbp_a` in calls.
    let decl: String = p.params.iter().map(|x| format!(", {} {}", scalar_type(&x.ty), param_var(&x.name))).collect();
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();
    let own = |s: &str| s.trim_start_matches(", ").to_string();
    let versions = p.versions.map(|_| p.version_bounds());
    out.line("");
    out.line("/** Decode from the start of {@code data}. Trailing bytes are ignored. */");
    out.open(format!("public static {} decode(byte[] data{}) {{", name, decl));
    out.line(format!("return decodeFrom(new PbReader(data){});", pass));
    out.close("}");
    if let Some((min, latest)) = versions {
        out.line("");
        out.line(format!(
            "/** Decode as protocol version {{@code version}} ({}..{}); 0: the one in the data, or the latest. */",
            min, latest
        ));
        out.open(format!("public static {} decode(byte[] data{}, int version) {{", name, decl));
        out.line("PbReader pbR = new PbReader(data);");
        out.line(format!("if (version != 0) pbR.setVersion(version, {}, {});", min, latest));
        out.line(format!("return decodeFrom(pbR{});", pass));
        out.close("}");
    }
    out.line("");
    out.open(format!("public static {} decodeFrom(PbReader pbR{}) {{", name, decl));
    out.line(format!("pbR.enter(\"{}\");", p.name));
    out.line(format!("{} p = new {}();", name, name));
    if p.needs_start(false) {
        out.line("long pb_start = pbR.positionBits();");
    }
    Decoder::new(p, zero_copy, outer).emit_steps(out);
    out.line("pbR.leave();");
    out.line("return p;");
    out.close("}");
    out.line("");
    out.open(format!("public byte[] encode({}) {{", own(&decl)));
    out.line("PbWriter pbW = new PbWriter();");
    out.line(format!("encodeTo(pbW{});", pass));
    out.line("return pbW.finish();");
    out.close("}");
    if let Some((min, latest)) = versions {
        out.line("");
        out.line(format!("/** Encode as protocol version {{@code version}} ({}..{}); 0: the latest. */", min, latest));
        out.open(format!("public byte[] encode({}int version) {{", own(&format!("{}, ", own(&decl)))));
        out.line("PbWriter pbW = new PbWriter();");
        out.line(format!("if (version != 0) pbW.setVersion(version, {}, {});", min, latest));
        out.line(format!("encodeTo(pbW{});", pass));
        out.line("return pbW.finish();");
        out.close("}");
    }
    out.line("");
    out.open(format!("public void encodeTo(PbWriter pbW{}) {{", decl));
    out.line(format!("pbW.enter(\"{}\");", p.name));
    out.line(format!("{} p = this;", name));
    if p.needs_start(true) {
        out.line("long pb_start = pbW.positionBits();");
    }
    let encoder = Encoder::new(p, outer);
    encoder.emit_locals(out);
    encoder.emit_steps(out);
    out.line("pbW.leave();");
    out.close("}");
    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
    out.close("}");
}
