//! A packet or union class in the module table, with its constructor and
//! `decode`/`encode` functions.

use super::decode::Decoder;
use super::encode::{Encoder, encode_locals};
use super::naming::{class, default_value, key};
use crate::generators::common::{Out, StepEmitter, member_category, param_var, string_literal};
use crate::ir::{Arm, Module, Packet, Union, ValueType};

/// The value an arm starts with.
fn arm_default(arm: &Arm) -> String {
    match (&arm.ty, arm.is_bytes()) {
        (None, _) => "nil".into(),
        (Some(_), true) => "\"\"".into(),
        (Some(ValueType::Packet(n)), false) => format!("{}.new()", class(n)),
        (Some(ValueType::Float { .. }), false) => "0.0".into(),
        (Some(ValueType::Mac), false) => "\"\\0\\0\\0\\0\\0\\0\"".into(),
        (Some(_), false) => "0".into(),
    }
}

/// `do local C = pb_class(); M.Name = C` ... `end`: the class of `name`.
fn open_class(out: &mut Out, name: &str, doc: &str) {
    out.open("do");
    out.line(format!("-- {}", doc));
    out.line("local C = pb_class()");
    out.line(format!("{} = C", class(name)));
}

/// A union: values are `{ kind = arm name, value = the arm's value }`.
pub fn emit_union(out: &mut Out, u: &Union) {
    let arms: Vec<&str> = u.arms.iter().map(|a| a.name.as_str()).collect();
    open_class(
        out,
        &u.name,
        &format!("{}: one arm of a union; `kind` is one of {}, `value` the arm's value.", u.name, arms.join(", ")),
    );
    out.line("");
    out.open("function C.new(kind, value)");
    out.line("return setmetatable({ kind = kind, value = value }, C)");
    out.close("end");
    out.line("");
    out.line("-- The first arm, holding its default value.");
    out.open("function C.default()");
    out.line(format!("return C.new({}, {})", string_literal(&u.arms[0].name), arm_default(&u.arms[0])));
    out.close("end");
    out.line("");
    super::json::emit_union_json(out, u);
    out.close("end");
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet) {
    open_class(out, &p.name, &format!("{}: a table of its fields, created by {}.new.", p.name, p.name));
    out.line("");
    out.line("-- A packet with every field at its default, then the fields of `init`.");
    out.open("function C.new(init)");
    if p.members.is_empty() {
        out.line("local p = setmetatable({}, C)");
    } else {
        out.open("local p = setmetatable({");
        for m in &p.members {
            let note = member_category(m).map(|c| format!(" -- values: {}", c)).unwrap_or_default();
            out.line(format!("{}{},{}", key(&m.name), default_value(m), note));
        }
        out.close("}, C)");
    }
    out.line("if init then for k, v in pairs(init) do p[k] = v end end");
    out.line("return p");
    out.close("end");
    out.line("");

    // Parameters: `, pbp_a` in signatures and calls.
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();
    // Files with versions: an optional protocol version to code as.
    let versions = p.versions.map(|_| p.version_bounds());
    let vparam = if versions.is_some() { ", version" } else { "" };
    match versions {
        Some((min, latest)) => {
            out.line(format!(
                "-- Decode from the start of `data` as protocol `version` ({}..{}; default: the",
                min, latest
            ));
            out.line("-- version in the data, or the latest). Trailing bytes are ignored.");
        }
        None => out.line("-- Decode from the start of `data` (a string). Trailing bytes are ignored."),
    }
    out.open(format!("function C.decode(data{}{})", pass, vparam));
    out.line("local r = pb_reader(data)");
    if let Some((min, latest)) = versions {
        out.line(format!("if version ~= nil then r:set_version(version, {}, {}) end", min, latest));
    }
    out.line(format!("return C.decode_from(r{})", pass));
    out.close("end");
    out.line("");
    out.open(format!("function C.decode_from(r{})", pass));
    out.line(format!("r:enter({})", string_literal(&p.name)));
    out.line("local p = C.new()");
    if p.needs_start(false) {
        out.line("local pb_start = r.pos");
    }
    out.line("local pb_c, pb_sel, pb_n, pb_j, pb_last");
    Decoder::new(p).emit_steps(out);
    out.line("r:leave()");
    out.line("return p");
    out.close("end");
    out.line("");

    out.line("-- The encoded packet, as a string.");
    out.open(format!("function C.encode(p{}{})", pass, vparam));
    out.line("local w = pb_writer()");
    if let Some((min, latest)) = versions {
        out.line(format!("if version ~= nil then w:set_version(version, {}, {}) end", min, latest));
    }
    out.line(format!("C.encode_to(p, w{})", pass));
    out.line("return w:finish()");
    out.close("end");
    out.line("");
    out.open(format!("function C.encode_to(p, w{})", pass));
    out.line(format!("w:enter({})", string_literal(&p.name)));
    if p.needs_start(true) {
        out.line("local pb_start = w.pos");
    }
    out.line("local pb_c, pb_sel, pb_v, pb_n, pb_b, pb_s");
    for chunk in encode_locals(p).chunks(16) {
        out.line(format!("local {}", chunk.join(", ")));
    }
    let encoder = Encoder::new(p);
    encoder.emit_locals(out);
    encoder.emit_steps(out);
    out.line("w:leave()");
    out.close("end");
    out.line("");

    out.line("-- Like decode and encode, but returning nil and the PbError instead of raising it.");
    out.open("function C.decode_safe(...)");
    out.line("return pb_protect(pcall(C.decode, ...))");
    out.close("end");
    out.line("");
    out.open("function C.encode_safe(...)");
    out.line("return pb_protect(pcall(C.encode, ...))");
    out.close("end");
    out.line("");
    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
    out.close("end");
}
