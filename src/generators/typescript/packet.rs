//! A TypeScript class with `decode`/`encode` methods for one packet, and the
//! type and helper object of a union.

use super::decode::Decoder;
use super::encode::Encoder;
use super::locals::emit_body;
use super::naming::{ident, is_big, member_default, member_type, scalar_type, type_name};
use crate::generators::common::{Out, StepEmitter, member_category, param_var};
use crate::ir::{Arm, Module, Packet, Union, ValueType};

/// The TypeScript type of an arm's value.
fn arm_type(arm: &Arm) -> String {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => "null".into(),
        (Some(_), true) => "Uint8Array".into(),
        (Some(t), false) => scalar_type(t),
    }
}

/// The value an arm starts with.
fn arm_default(arm: &Arm) -> String {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => "null".into(),
        (Some(_), true) => "new Uint8Array(0)".into(),
        (Some(ValueType::Packet(n)), false) => format!("new {}()", type_name(n)),
        (Some(ValueType::Mac), false) => "new Uint8Array(6)".into(),
        (Some(t), false) if is_big(t) => "0n".into(),
        (Some(_), false) => "0".into(),
    }
}

/// A union as a discriminated union type (`kind` names the arm, `value`
/// holds its value), and an object of the same name with its helpers.
pub fn emit_union(out: &mut Out, u: &Union) {
    let name = type_name(&u.name);
    let arms: Vec<String> = u.arms.iter().map(|a| a.name.clone()).collect();
    out.line(format!("/** One arm of a union: `kind` is one of {}; `value` is the arm's value. */", arms.join(", ")));
    out.line(format!("export type {} =", name));
    for (i, arm) in u.arms.iter().enumerate() {
        let end = if i + 1 == u.arms.len() { ";" } else { "" };
        out.line(format!("  | {{ kind: \"{}\"; value: {} }}{}", arm.name, arm_type(arm), end));
    }
    out.line("");
    out.open(format!("export const {} = {{", name));
    out.line("/** The first arm, holding its default value. */");
    out.open(format!("pbDefault(): {} {{", name));
    out.line(format!("return {{ kind: \"{}\", value: {} }};", u.arms[0].name, arm_default(&u.arms[0])));
    out.close("},");
    super::json::emit_union_json(out, u);
    out.close("};");
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet, zero_copy: bool) {
    let name = type_name(&p.name);
    out.open(format!("export class {} {{", name));
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/** Values: `{}`. */", cat));
        }
        out.line(format!("{}: {} = {};", ident(&m.name), member_type(m), member_default(m)));
    }
    if !p.members.is_empty() {
        out.line("");
    }
    // Parameters: `, pbp_a: number` in signatures and `, pbp_a` in calls.
    let sig: String = p.params.iter().map(|x| format!(", {}: {}", param_var(&x.name), scalar_type(&x.ty))).collect();
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();
    // Files with versions: an optional protocol version to code as.
    let versions = p.versions.map(|_| p.version_bounds());
    let ver_sig = if versions.is_some() { ", version?: number" } else { "" };

    match versions {
        Some((min, latest)) => {
            out.line(format!(
                "/** Decode from the start of `data` as protocol `version` ({}..{}; default: the",
                min, latest
            ));
            out.line(" * version in the data, or the latest). Trailing bytes are ignored. */");
        }
        None => out.line("/** Decode from the start of `data`. Trailing bytes are ignored. */"),
    }
    out.open(format!("static decode(data: Uint8Array{}{}): {} {{", sig, ver_sig, name));
    out.line("const pb_r = new PbReader(data);");
    if let Some((min, latest)) = versions {
        out.line(format!("if (version !== undefined) pb_r.setVersion(version, {}, {});", min, latest));
    }
    out.line(format!("return {}.decodeFrom(pb_r{});", name, pass));
    out.close("}");
    out.line("");
    out.open(format!("static decodeFrom(pb_r: PbReader{}): {} {{", sig, name));
    out.line(format!("pb_r.enter(\"{}\");", p.name));
    if let Some(scope) = p.version_scope {
        out.line(format!("const pb_scope = pb_r.enterScope({});", scope));
    }
    out.line(format!("const p = new {}();", name));
    if p.needs_start(false) {
        out.line("const pb_start = pb_r.positionBits();");
    }
    let decoder = Decoder::new(p, zero_copy);
    emit_body(out, 2, &decoder.locals, |body| decoder.emit_steps(body));
    if p.version_scope.is_some() {
        out.line("pb_r.leaveScope(pb_scope);");
    }
    out.line("pb_r.leave();");
    out.line("return p;");
    out.close("}");
    out.line("");

    out.open(format!("encode({}{}): Uint8Array {{", sig.trim_start_matches(", "), ver_sig_first(&sig, ver_sig)));
    out.line("const pb_w = new PbWriter();");
    if let Some((min, latest)) = versions {
        out.line(format!("if (version !== undefined) pb_w.setVersion(version, {}, {});", min, latest));
    }
    out.line(format!("this.encodeTo(pb_w{});", pass));
    out.line("return pb_w.finish();");
    out.close("}");
    out.line("");
    out.open(format!("encodeTo(pb_w: PbWriter{}): void {{", sig));
    out.line(format!("pb_w.enter(\"{}\");", p.name));
    if let Some(scope) = p.version_scope {
        out.line(format!("const pb_scope = pb_w.enterScope({});", scope));
    }
    out.line("const p = this;");
    if p.needs_start(true) {
        out.line("const pb_start = pb_w.positionBits();");
    }
    let encoder = Encoder::new(p);
    emit_body(out, 2, &encoder.locals, |body| {
        encoder.emit_locals(body);
        encoder.emit_steps(body);
    });
    if p.version_scope.is_some() {
        out.line("pb_w.leaveScope(pb_scope);");
    }
    out.line("pb_w.leave();");
    out.close("}");
    out.line("");
    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
    out.close("}");
}

/// The `version?` parameter of `encode`, after the packet's own parameters
/// (without a leading comma when there are none).
fn ver_sig_first(sig: &str, ver_sig: &str) -> String {
    if sig.is_empty() { ver_sig.trim_start_matches(", ").to_string() } else { ver_sig.to_string() }
}
