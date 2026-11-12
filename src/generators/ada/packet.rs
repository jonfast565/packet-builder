//! The subprograms of each packet: `Decode`, `Decode_From`, `Encode`,
//! `Encode_To` (declared in the spec, implemented after the runtime), plus
//! `To_Json` and the stream helpers.

use super::decode::Decoder;
use super::encode::Encoder;
use super::locals::{Locals, body};
use super::naming::{param_var, scalar_type, type_name};
use super::stream::{safety_net, set_version};
use super::types::Boxes;
use crate::generators::common::{Out, StepEmitter};
use crate::ir::{Module, Packet};

/// `; Pbp_A : Unsigned_8; Pbp_B : Integer_16`: the packet's parameters.
fn param_decl(p: &Packet) -> String {
    p.params.iter().map(|x| format!("; {} : {}", param_var(&x.name), scalar_type(&x.ty))).collect()
}

/// `, Pbp_A, Pbp_B`: the parameters passed on.
fn param_pass(p: &Packet) -> String {
    p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect()
}

/// `; Version : Integer_64 := 0` (Ada wants the default in the spec and the
/// body alike).
pub fn version_param(p: &Packet) -> String {
    match p.versions {
        Some(_) => "; Version : Integer_64 := 0".to_string(),
        None => String::new(),
    }
}

fn decode_header(p: &Packet) -> String {
    format!("function Decode (Data : Pb_Byte_Array{}{}) return {}", param_decl(p), version_param(p), type_name(&p.name))
}

fn decode_from_header(p: &Packet) -> String {
    format!("function Decode_From (R : not null access Pb_Reader{}) return {}", param_decl(p), type_name(&p.name))
}

fn encode_header(p: &Packet) -> String {
    format!("function Encode (P : {}{}{}) return Pb_Byte_Array", type_name(&p.name), param_decl(p), version_param(p))
}

fn encode_to_header(p: &Packet) -> String {
    format!("procedure Encode_To (P : {}; W : not null access Pb_Writer{})", type_name(&p.name), param_decl(p))
}

pub fn declare_packet(out: &mut Out, module: &Module, p: &Packet) {
    out.line("");
    out.line(format!("--  ---- {} ----", p.name));
    match p.versions.map(|_| p.version_bounds()) {
        Some((min, latest)) => out.line(format!(
            "--  Decode from the start of Data; trailing bytes are ignored. Version: the protocol version ({}..{}); 0: the one in the data, or the latest.",
            min, latest
        )),
        None => out.line("--  Decode from the start of Data; trailing bytes are ignored."),
    }
    out.line(format!("{};", decode_header(p)));
    out.line(format!("{};", decode_from_header(p)));
    out.line(format!("{};", encode_header(p)));
    out.line(format!("{};", encode_to_header(p)));
    super::json::declare_packet_json(out, p);
    super::stream::declare_streaming(out, module, p);
}

pub fn implement_packet(out: &mut Out, module: &Module, p: &Packet, boxes: &Boxes) {
    let name = type_name(&p.name);
    let pass = param_pass(p);

    out.line("");
    out.line(format!("{} is", decode_header(p)));
    out.line("begin");
    out.push();
    out.open("declare");
    out.line("Pb_Rd : aliased Pb_Reader (Data'Length);");
    out.close("begin");
    out.push();
    out.line("Pb_Init (Pb_Rd, Data);");
    set_version(out, p, "Pb_Rd");
    out.line(format!("return Decode_From (Pb_Rd'Access{});", pass));
    out.pop();
    out.line("end;");
    out.pop();
    safety_net(out, "Decode");

    out.line("");
    let locals = Locals::default();
    locals.var("P", &name);
    let mut b = body();
    b.line(format!("Pb_Enter (R, \"{}\");", p.name));
    if p.needs_start(false) {
        locals.var("pb_start", "Integer_64");
        b.line("pb_start := Pb_Pos (R);");
    }
    Decoder::new(p, &locals, boxes).emit_steps(&mut b);
    b.line("Pb_Leave (R);");
    b.line("return P;");
    locals.routine(out, &decode_from_header(p), "Decode_From", b);

    out.line("");
    out.line(format!("{} is", encode_header(p)));
    out.line("begin");
    out.push();
    out.open("declare");
    out.line("Pb_Wr : aliased Pb_Writer;");
    out.close("begin");
    out.push();
    set_version(out, p, "Pb_Wr");
    out.line(format!("Encode_To (P, Pb_Wr'Access{});", pass));
    out.line("return Pb_Finish (Pb_Wr'Access);");
    out.pop();
    out.line("end;");
    out.pop();
    safety_net(out, "Encode");

    out.line("");
    let locals = Locals::default();
    let mut b = body();
    b.line(format!("Pb_Enter (W, \"{}\");", p.name));
    if p.needs_start(true) {
        locals.var("pb_start", "Integer_64");
        b.line("pb_start := Pb_Pos (W);");
    }
    let encoder = Encoder::new(p, &locals, boxes);
    encoder.emit_locals(&mut b);
    encoder.emit_steps(&mut b);
    b.line("Pb_Leave (W);");
    locals.routine(out, &encode_to_header(p), "Encode_To", b);

    super::json::implement_packet_json(out, p, boxes);
    super::stream::implement_streaming(out, module, p);
}
