//! A class per packet with `Decode`/`Encode` methods, and a class per union
//! with a subclass per arm. Each is declared in the interface and
//! implemented after the runtime.

use super::decode::Decoder;
use super::encode::Encoder;
use super::locals::{Locals, body};
use super::naming::{arm_class, default_value, ident, member_type, owns_objects, scalar_type, type_name};
use crate::generators::common::{Out, StepEmitter, member_category, param_var};
use crate::ir::{Module, Packet, Union, ValueType};

/// What a union arm's `Value` starts as in `PbDefault`.
fn arm_default(ty: &ValueType, bytes: bool) -> String {
    match ty {
        _ if bytes => "nil".into(),
        ValueType::Packet(n) => format!("{}.Create", type_name(n)),
        ValueType::Union(n) => format!("{}.PbDefault", type_name(n)),
        ValueType::Mac => "PbZeros(6)".into(),
        ValueType::Str => "''".into(),
        _ => "0".into(),
    }
}

fn arm_value_type(ty: &ValueType, bytes: bool) -> String {
    if bytes { "TBytes".into() } else { scalar_type(ty) }
}

pub fn declare_union(out: &mut Out, u: &Union) {
    let base = type_name(&u.name);
    out.line(format!("/// One arm of union {}: the subclass says which.", u.name));
    out.line(format!("{} = class", base));
    out.line("public");
    out.push();
    out.line(format!("class function PbDefault: {};", base));
    out.line("function ToJson: string; virtual; abstract;");
    out.pop();
    out.line("end;");
    for arm in &u.arms {
        out.line("");
        if arm.default {
            out.line("/// Any other selector value.");
        } else {
            let v: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            out.line(format!("/// Selector {}.", v.join(", ")));
        }
        out.line(format!("{} = class({})", arm_class(&u.name, arm), base));
        out.line("public");
        out.push();
        if let Some(t) = &arm.ty {
            out.line(format!("Value: {};", arm_value_type(t, arm.is_bytes())));
            out.line(format!("constructor Create(const AValue: {});", arm_value_type(t, arm.is_bytes())));
            if !arm.is_bytes() && matches!(t, ValueType::Packet(_) | ValueType::Union(_)) {
                out.line("destructor Destroy; override;");
            }
        }
        out.line("function ToJson: string; override;");
        out.pop();
        out.line("end;");
    }
}

pub fn implement_union(out: &mut Out, u: &Union) {
    let base = type_name(&u.name);
    let first = &u.arms[0];
    out.line("");
    out.line(format!("class function {}.PbDefault: {};", base, base));
    out.open("begin");
    match &first.ty {
        Some(t) => {
            out.line(format!("Result := {}.Create({});", arm_class(&u.name, first), arm_default(t, first.is_bytes())))
        }
        None => out.line(format!("Result := {}.Create;", arm_class(&u.name, first))),
    }
    out.close("end;");
    for arm in &u.arms {
        let class = arm_class(&u.name, arm);
        if let Some(t) = &arm.ty {
            out.line("");
            out.line(format!("constructor {}.Create(const AValue: {});", class, arm_value_type(t, arm.is_bytes())));
            out.open("begin");
            out.line("inherited Create;");
            out.line("Value := AValue;");
            out.close("end;");
            if !arm.is_bytes() && matches!(t, ValueType::Packet(_) | ValueType::Union(_)) {
                out.line("");
                out.line(format!("destructor {}.Destroy;", class));
                out.open("begin");
                out.line("Value.Free;");
                out.line("inherited Destroy;");
                out.close("end;");
            }
        }
        super::json::implement_arm_json(out, u, arm);
    }
}

/// `; pbp_a: UInt8; pbp_b: Int16`: the packet's parameters in a signature.
fn param_decl(p: &Packet) -> String {
    p.params.iter().map(|x| format!("; {}: {}", param_var(&x.name), scalar_type(&x.ty))).collect()
}

/// `, pbp_a, pbp_b`: the parameters passed on.
fn param_pass(p: &Packet) -> String {
    p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect()
}

/// The parameter list of `Encode` (empty, or `(...)`), with the defaults
/// in the declaration only.
fn encode_params(p: &Packet, defaults: bool) -> String {
    let mut parts: Vec<String> =
        p.params.iter().map(|x| format!("{}: {}", param_var(&x.name), scalar_type(&x.ty))).collect();
    if p.versions.is_some() {
        parts.push(format!("AVersion: Integer{}", if defaults { " = 0" } else { "" }));
    }
    if parts.is_empty() { String::new() } else { format!("({})", parts.join("; ")) }
}

fn version_param(p: &Packet, defaults: bool) -> String {
    match p.versions {
        Some(_) => format!("; AVersion: Integer{}", if defaults { " = 0" } else { "" }),
        None => String::new(),
    }
}

pub fn declare_packet(out: &mut Out, module: &Module, p: &Packet) {
    let name = type_name(&p.name);
    out.line(format!("{} = class", name));
    out.line("public");
    out.push();
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/// Values from T{}.", cat));
        }
        out.line(format!("{}: {};", ident(&m.name), member_type(m)));
    }
    out.line("constructor Create;");
    out.line("destructor Destroy; override;");
    if let Some((min, latest)) = p.versions.map(|_| p.version_bounds()) {
        out.line(format!(
            "/// Decode from the start of AData; trailing bytes are ignored. AVersion: the protocol version ({}..{}); 0: the one in the data, or the latest.",
            min, latest
        ));
    } else {
        out.line("/// Decode from the start of AData; trailing bytes are ignored.");
    }
    out.line(format!(
        "class function Decode(const AData: TBytes{}{}): {};",
        param_decl(p),
        version_param(p, true),
        name
    ));
    out.line(format!("class function DecodeFrom(pbR: TPbReader{}): {};", param_decl(p), name));
    out.line(format!("function Encode{}: TBytes;", encode_params(p, true)));
    out.line(format!("procedure EncodeTo(pbW: TPbWriter{});", param_decl(p)));
    out.line("/// The value as JSON: numbers, bytes as hex strings, unions as {\"kind\", \"value\"}.");
    out.line("function ToJson: string;");
    super::stream::declare_streaming(out, module, p);
    out.pop();
    out.line("end;");
}

pub fn implement_packet(out: &mut Out, module: &Module, p: &Packet) {
    let name = type_name(&p.name);
    let pass = param_pass(p);
    let versions = p.versions.map(|_| p.version_bounds());

    out.line("");
    out.line(format!("constructor {}.Create;", name));
    out.open("begin");
    out.line("inherited Create;");
    for m in &p.members {
        if let Some(d) = default_value(m) {
            out.line(format!("{} := {};", ident(&m.name), d));
        }
    }
    out.close("end;");

    out.line("");
    out.line(format!("destructor {}.Destroy;", name));
    let owned: Vec<_> = p.members.iter().filter(|m| owns_objects(m)).collect();
    if owned.iter().any(|m| m.array.is_some()) {
        out.open("var");
        out.line("pbI: Integer;");
        out.pop();
    }
    out.open("begin");
    for m in &owned {
        let f = ident(&m.name);
        match m.array {
            Some(_) => out.line(format!("for pbI := 0 to High({}) do {}[pbI].Free;", f, f)),
            None => out.line(format!("{}.Free;", f)),
        }
    }
    out.line("inherited Destroy;");
    out.close("end;");

    out.line("");
    out.line(format!(
        "class function {}.Decode(const AData: TBytes{}{}): {};",
        name,
        param_decl(p),
        version_param(p, false),
        name
    ));
    out.open("var");
    out.line("pbR: TPbReader;");
    out.pop();
    out.open("begin");
    out.line("pbR := TPbReader.Create(AData);");
    out.open("try");
    if let Some((min, latest)) = versions {
        out.line(format!("if AVersion <> 0 then pbR.SetVersion(AVersion, {}, {});", min, latest));
    }
    out.line(format!("Result := DecodeFrom(pbR{});", pass));
    out.close("finally");
    out.push();
    out.line("pbR.Free;");
    out.close("end;");
    out.close("end;");

    out.line("");
    out.line(format!("class function {}.DecodeFrom(pbR: TPbReader{}): {};", name, param_decl(p), name));
    let locals = Locals::default();
    locals.var("p", &name);
    let mut b = body();
    b.line(format!("pbR.Enter('{}');", p.name));
    b.line(format!("p := {}.Create;", name));
    b.open("try");
    if p.needs_start(false) {
        locals.var("pb_start", "Int64");
        b.line("pb_start := pbR.PositionBits;");
    }
    Decoder::new(p, &locals).emit_steps(&mut b);
    b.close("except");
    b.push();
    b.line("p.Free;");
    b.line("raise;");
    b.close("end;");
    b.line("pbR.Leave;");
    b.line("Result := p;");
    locals.routine(out, b);

    out.line("");
    out.line(format!("function {}.Encode{}: TBytes;", name, encode_params(p, false)));
    out.open("var");
    out.line("pbW: TPbWriter;");
    out.pop();
    out.open("begin");
    out.line("pbW := TPbWriter.Create;");
    out.open("try");
    if let Some((min, latest)) = versions {
        out.line(format!("if AVersion <> 0 then pbW.SetVersion(AVersion, {}, {});", min, latest));
    }
    out.line(format!("EncodeTo(pbW{});", pass));
    out.line("Result := pbW.Finish;");
    out.close("finally");
    out.push();
    out.line("pbW.Free;");
    out.close("end;");
    out.close("end;");

    out.line("");
    out.line(format!("procedure {}.EncodeTo(pbW: TPbWriter{});", name, param_decl(p)));
    let locals = Locals::default();
    locals.var("p", &name);
    let mut b = body();
    b.line(format!("pbW.Enter('{}');", p.name));
    b.line("p := Self;");
    if p.needs_start(true) {
        locals.var("pb_start", "Int64");
        b.line("pb_start := pbW.PositionBits;");
    }
    let encoder = Encoder::new(p, &locals);
    encoder.emit_locals(&mut b);
    encoder.emit_steps(&mut b);
    b.line("pbW.Leave;");
    locals.routine(out, b);

    super::json::implement_packet_json(out, p);
    super::stream::implement_streaming(out, module, p);
}
