//! `P_to_json`: every packet as a JSON string. Integers are numbers, bytes
//! are hex strings, unions are `{"kind": arm, "value": ...}`.

use super::naming::{ident, len_ident};
use super::packet::arm_kind;
use crate::generators::common::Out;
use crate::ir::{Member, Module, Packet, Union, ValueType};

/// The prototype in the header.
pub fn declare_json(out: &mut Out, p: &Packet) {
    out.line("/* The value as JSON (numbers, bytes as hex strings, unions as {\"kind\", \"value\"}),");
    out.line(" * in a new NUL-terminated buffer the caller frees; NULL when out of memory. */");
    out.line(format!("char *{}_to_json(const {} *p);", p.name, p.name));
}

/// Forward declarations of the writers, which may call each other.
pub fn emit_json_prototypes(out: &mut Out, module: &Module) {
    for u in &module.unions {
        out.line(format!("PB_FN void pb_json_{}(pb_sb *b, const {} *v);", u.name, u.name));
    }
    for p in &module.packets {
        out.line(format!("PB_FN void pb_json_{}(pb_sb *b, const {} *p);", p.name, p.name));
    }
}

fn elem(ty: &ValueType, v: &str) -> String {
    match ty {
        ValueType::Int { signed: true, .. } => format!("pb_sb_i64(b, (int64_t){});", v),
        ValueType::Int { .. } => format!("pb_sb_u64(b, (uint64_t){});", v),
        ValueType::Float { .. } => format!("pb_sb_f64(b, (double){});", v),
        ValueType::Mac => format!("pb_sb_hex(b, {}, 6);", v),
        ValueType::Str => unreachable!("strings carry a length"),
        ValueType::Packet(n) | ValueType::Union(n) => format!("pb_json_{}(b, &{});", n, v),
    }
}

fn member(out: &mut Out, p: &Packet, m: &Member) {
    let place = format!("p->{}", ident(&m.name));
    let len = format!("p->{}", len_ident(p, m));
    match (&m.array, &m.ty) {
        (None, ValueType::Str) => out.line(format!("pb_sb_str(b, {}, {});", place, len)),
        (None, ty) => out.line(elem(ty, &place)),
        (Some(_), ty) if ty.is_byte() => out.line(format!("pb_sb_hex(b, {}, {});", place, len)),
        (Some(_), ty) => {
            out.line("pb_sb_puts(b, \"[\");");
            out.open(format!("for (i = 0; i < {}; i++) {{", len));
            out.line("if (i) pb_sb_puts(b, \",\");");
            out.line(elem(ty, &format!("{}[i]", place)));
            out.close("}");
            out.line("pb_sb_puts(b, \"]\");");
        }
    }
}

pub fn emit_packet_json(out: &mut Out, p: &Packet) {
    out.line("");
    out.open(format!("PB_FN void pb_json_{}(pb_sb *b, const {} *p) {{", p.name, p.name));
    out.line("size_t i = 0;");
    out.line("(void)i;");
    out.line("(void)p;");
    out.line("pb_sb_puts(b, \"{\");");
    for (k, m) in p.members.iter().enumerate() {
        out.line(format!("pb_sb_puts(b, \"{}\\\"{}\\\":\");", if k > 0 { "," } else { "" }, m.name));
        member(out, p, m);
    }
    out.line("pb_sb_puts(b, \"}\");");
    out.close("}");
    out.line("");
    out.open(format!("char *{}_to_json(const {} *p) {{", p.name, p.name));
    out.line("pb_sb b = { NULL, 0, 0, 0 };");
    out.line(format!("pb_json_{}(&b, p);", p.name));
    out.line("return pb_sb_finish(&b);");
    out.close("}");
}

pub fn emit_union_json(out: &mut Out, u: &Union) {
    out.line("");
    out.open(format!("PB_FN void pb_json_{}(pb_sb *b, const {} *v) {{", u.name, u.name));
    out.open("switch (v->kind) {");
    for arm in &u.arms {
        let id = ident(&arm.name);
        out.line(format!("case {}:", arm_kind(&u.name, arm)));
        out.push();
        out.line(format!("pb_sb_puts(b, \"{{\\\"kind\\\":\\\"{}\\\",\\\"value\\\":\");", arm.name));
        match (&arm.ty, arm.is_bytes()) {
            (None, _) => out.line("pb_sb_puts(b, \"null\");"),
            (Some(_), true) => out.line(format!("pb_sb_hex(b, v->u.{}.data, v->u.{}.len);", id, id)),
            (Some(t), _) => out.line(elem(t, &format!("v->u.{}", id))),
        }
        out.line("pb_sb_puts(b, \"}\");");
        out.line("break;");
        out.pop();
    }
    out.line("default:");
    out.line("    pb_sb_puts(b, \"null\");");
    out.close("}");
    out.close("}");
}
