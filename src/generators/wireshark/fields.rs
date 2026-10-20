//! ProtoField declarations: one per member (and per union arm holding an
//! integer or bytes), and value-string tables for categories.

use super::naming::{field_abbrev, field_key};
use crate::generators::common::{Out, member_category, string_literal};
use crate::ir::{Member, Module, ValueType, storage_for};

/// `ProtoField.uint16(...)` and the value kind `pb_wsval` converts for,
/// for a value of type `ty` (`bytes` for a byte array).
fn proto_field(
    abbrev: &str,
    label: &str,
    ty: &ValueType,
    bytes: bool,
    base: &str,
    vs: Option<&str>,
) -> Option<(String, &'static str)> {
    let name = format!("abbrev .. \".{}\"", abbrev);
    let label = string_literal(label);
    if bytes {
        return Some((format!("ProtoField.bytes({}, {})", name, label), "bytes"));
    }
    Some(match ty {
        ValueType::Int { width, signed } => {
            let bits = storage_for(*width);
            let kind = match (bits, signed) {
                (64, false) => "u64",
                (64, true) => "i64",
                _ => "int",
            };
            let vs = if bits <= 32 {
                vs.map(|v| format!(", VS[{}]", string_literal(v))).unwrap_or_default()
            } else {
                String::new()
            };
            (
                format!(
                    "ProtoField.{}{}({}, {}, {}{})",
                    if *signed { "int" } else { "uint" },
                    bits,
                    name,
                    label,
                    base,
                    vs
                ),
                kind,
            )
        }
        ValueType::Float { width: 32 } => (format!("ProtoField.float({}, {})", name, label), "int"),
        ValueType::Float { .. } => (format!("ProtoField.double({}, {})", name, label), "int"),
        ValueType::Mac => (format!("ProtoField.bytes({}, {}, base.COLON)", name, label), "bytes"),
        ValueType::Str => (format!("ProtoField.string({}, {})", name, label), "int"),
        ValueType::Packet(_) | ValueType::Union(_) => return None,
    })
}

fn member_field(out: &mut Out, owner: &str, m: &Member) {
    let base = if m.magic().is_some() { "base.HEX" } else { "base.DEC" };
    let bytes = m.array.is_some() && m.ty.is_byte();
    let signed_base = if m.ty.is_signed() { "base.DEC" } else { base };
    if let Some((decl, kind)) =
        proto_field(&field_abbrev(owner, &m.name), &m.name, &m.ty, bytes, signed_base, member_category(m))
    {
        out.line(format!("F[{}] = {{ field = {}, kind = \"{}\" }}", field_key(owner, &m.name), decl, kind));
    }
}

/// `VS` (category value strings) and `make_fields(abbrev)`, which builds a
/// protocol's field table keyed by `"Packet.member"`.
pub fn emit_fields(out: &mut Out, module: &Module) {
    out.line("local VS = {}");
    for cat in &module.categories {
        let items: Vec<String> =
            cat.members.iter().map(|c| format!("[{}] = {}", c.value, string_literal(&c.name))).collect();
        out.line(format!("VS[{}] = {{ {} }}", string_literal(&cat.name), items.join(", ")));
    }
    out.line("");
    out.open("local function make_fields(abbrev)");
    out.line("local F = {}");
    for p in &module.packets {
        for m in &p.members {
            member_field(out, &p.name, m);
        }
    }
    for u in &module.unions {
        for arm in &u.arms {
            let Some(ty) = &arm.ty else { continue };
            if let Some((decl, kind)) =
                proto_field(&field_abbrev(&u.name, &arm.name), &arm.name, ty, arm.is_bytes(), "base.DEC", None)
            {
                out.line(format!("F[{}] = {{ field = {}, kind = \"{}\" }}", field_key(&u.name, &arm.name), decl, kind));
            }
        }
    }
    out.line("return F");
    out.close("end");
}
