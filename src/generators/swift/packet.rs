//! A Swift struct with `decode`/`encode` methods for one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{Types, case_name, default_value, ident, member_default, scalar_type};
use crate::generators::common::{Out, StepEmitter, magic_literal, member_category, param_var};
use crate::ir::{Module, Packet, Union};

/// A Swift enum with one case per arm.
pub fn emit_union(out: &mut Out, u: &Union, types: &Types) {
    out.open(format!("public enum {}: Equatable {{", u.name));
    for arm in &u.arms {
        let values: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
        out.line(format!(
            "/// {}",
            if arm.default { "Any other selector value.".into() } else { format!("Selector {}.", values.join(", ")) }
        ));
        match types.arm(arm) {
            Some(t) => out.line(format!("case {}({})", case_name(arm), t)),
            None => out.line(format!("case {}", case_name(arm))),
        }
    }
    out.line("");
    out.line("/// The first arm, holding its zero value.");
    out.open("public init() {");
    let first = &u.arms[0];
    match (&first.ty, first.is_bytes()) {
        (None, _) => out.line(format!("self = .{}", case_name(first))),
        (Some(_), true) => out.line(format!("self = .{}([])", case_name(first))),
        (Some(t), false) => out.line(format!("self = .{}({})", case_name(first), default_value(t))),
    }
    out.close("}");
    super::json::emit_union_json(out, u);
    out.close("}");
}

pub fn emit_packet(out: &mut Out, module: &Module, p: &Packet, types: &Types) {
    let name = &p.name;

    if types.borrowing.contains(name) {
        out.line("/// Byte buffers are slices sharing the decoded input's storage.");
    }
    out.open(format!("public struct {}: Equatable {{", name));
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/// Values from `{}`.", ident(cat)));
        }
        let v = magic_literal(m).unwrap_or_else(|| member_default(m));
        out.line(format!("public var {}: {} = {}", ident(&m.name), types.member(m), v));
    }
    if !p.members.is_empty() {
        out.line("");
    }
    out.line("public init() {}");
    out.line("");

    // Parameters: `, _ pbp_a: UInt8` in signatures, `, pbp_a` in calls.
    let decl: String = p.params.iter().map(|x| format!(", _ {}: {}", param_var(&x.name), scalar_type(&x.ty))).collect();
    let first_decl = decl.strip_prefix(", ").unwrap_or("").to_string();
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();

    // decode
    out.line("/// Decode from the start of `data`. Trailing bytes are ignored.");
    out.open(format!("public static func decode(_ data: [UInt8]{}) throws -> {} {{", decl, name));
    out.line("let pbR = PbReader(data)");
    out.line(format!("return try {}.decodeFrom(pbR{})", name, pass));
    out.close("}");
    out.line("");
    let versions = p.versions.map(|_| p.version_bounds());
    if let Some((min, latest)) = versions {
        out.line(format!("/// Decode as protocol version `version` ({}...{}).", min, latest));
        out.open(format!("public static func decode(_ data: [UInt8], version: Int{}) throws -> {} {{", decl, name));
        out.line("let pbR = PbReader(data)");
        out.line(format!("try pbR.setVersion(Int64(version), {}, {})", min, latest));
        out.line(format!("return try {}.decodeFrom(pbR{})", name, pass));
        out.close("}");
        out.line("");
    }
    out.open(format!("public static func decodeFrom(_ pbR: PbReader{}) throws -> {} {{", decl, name));
    out.line(format!("try pbR.enter(\"{}\")", name));
    out.line(format!("var p = {}()", name));
    if p.needs_start(false) {
        out.line("let pb_start = pbR.positionBits()");
    }
    Decoder::new(p, types.zero_copy).emit_steps(out);
    out.line("pbR.leave()");
    out.line("return p");
    out.close("}");
    out.line("");

    // encode
    out.open(format!("public func encode({}) throws -> [UInt8] {{", first_decl));
    out.line("let pbW = PbWriter()");
    out.line(format!("try encodeTo(pbW{})", pass));
    out.line("return try pbW.finish()");
    out.close("}");
    out.line("");
    if let Some((min, latest)) = versions {
        out.line(format!("/// Encode as protocol version `version` ({}...{}).", min, latest));
        out.open(format!("public func encode(version: Int{}) throws -> [UInt8] {{", decl));
        out.line("let pbW = PbWriter()");
        out.line(format!("try pbW.setVersion(Int64(version), {}, {})", min, latest));
        out.line(format!("try encodeTo(pbW{})", pass));
        out.line("return try pbW.finish()");
        out.close("}");
        out.line("");
    }
    out.open(format!("public func encodeTo(_ pbW: PbWriter{}) throws {{", decl));
    out.line(format!("try pbW.enter(\"{}\")", name));
    out.line("let p = self");
    if p.needs_start(true) {
        out.line("let pb_start = pbW.positionBits()");
    }
    let encoder = Encoder::new(p);
    encoder.emit_locals(out);
    encoder.emit_steps(out);
    out.line("_ = p");
    out.line("pbW.leave()");
    out.close("}");

    super::json::emit_packet_json(out, p);
    super::stream::emit_streaming(out, module, p);
    out.close("}");
}
