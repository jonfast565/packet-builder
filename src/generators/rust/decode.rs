//! Rust decoder statements.

use super::expr::store_value;
use super::naming::{Rust, ident, scalar_type};
use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, TextEncoding, ValueType};

/// Expression that reads one element.
fn read_elem(codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let signed = ty.is_signed();
    let width = match ty {
        ValueType::Int { width, .. } => *width,
        _ => 0,
    };
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
        Codec::Bits { width } => format!("pb_r.read_bits({})?", width),
        Codec::Float { width: 32, endian } => {
            return format!("f32::from_bits(pb_r.read_uint(4, {})? as u32)", Rust::little(endian));
        }
        Codec::Float { endian, .. } => return format!("f64::from_bits(pb_r.read_uint(8, {})?)", Rust::little(endian)),
        Codec::Mac => return "pb_r.read_mac()?".into(),
        Codec::Varint(k) => format!("pb_r.read_varint({})?", k.id()),
        Codec::Packet(n) => return format!("{}::decode_from(pb_r)?", n),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    if signed { format!("pb_sext({}, {}) as {}", raw, width, st) } else { format!("{} as {}", raw, st) }
}

/// `[0x0d, 0x0a]`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}u8", b)).collect();
    format!("[{}]", items.join(", "))
}

pub struct Decoder<'a> {
    scope: Scope<'a, Rust>,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode) }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let v = variant_name(arm);
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => format!("{}::{}", u, v),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("{}::{}(pb_r.read_bytes(pb_r.count({}, 8)?)?)", u, v, self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("{}::{}(pb_r.read_bytes(pb_r.remaining_bits() / 8)?)", u, v)
            }
            (Some(ty), Some(codec), None) => format!("{}::{}({})", u, v, read_elem(codec, ty)),
            _ => format!("{}::{}(Default::default())", u, v),
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if !{} {{ return Err(pb_r.error(PbErrorKind::Constraint, {}.into())); }}",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_r.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        out.open("{");
        out.line(format!("let pb_sel: i64 = {};", self.scope.expr(selector)));
        out.open(format!("p.{} = match pb_sel {{", ident(&m.name)));
        for arm in arms.iter().filter(|a| !a.default) {
            let pat: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            out.line(format!("{} => {},", pat.join(" | "), self.arm_value(u, arm)));
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => out.line(format!("_ => {},", self.arm_value(u, arm))),
            None => out.line(format!(
                "_ => return Err(pb_r.error(PbErrorKind::Invalid, format!(\"no arm of `{}` for {{}}\", pb_sel))),",
                m.name
            )),
        }
        out.close("};");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("let pb_win{} = pb_r.push_limit({})?;", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pb_r.pop_limit(pb_win{}, {})?;", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("let {} = pb_r.position_bits();", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if (p.{} as i64) != {} {{ return Err(pb_r.error(PbErrorKind::Mismatch, {}.into())); }}",
            ident(&m.name),
            self.scope.expr(value),
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_r.skip_bits(pb_pad(pb_r.position_bits() - pb_start, {}))?;", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {};", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pb_r.read_cstring()?".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pb_r.read_until(&{}, {})?", byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                let len = read_elem(prefix, &PREFIX_LEN);
                format!("{{ let pb_n = {} as i64; pb_r.read_bytes(pb_r.count(pb_n, 8)?)? }}", len)
            }
            (_, Some(Count::Expr(e))) => format!("pb_r.read_bytes(pb_r.count({}, 8)?)?", self.scope.expr(e)),
            _ => "pb_r.read_bytes(pb_r.remaining_bits() / 8)?".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        out.open("{");
        if m.encoding == TextEncoding::Utf8 {
            let raw = if padded { format!("pb_until_nul({})", raw) } else { raw };
            out.line(format!("let pb_t = {};", raw));
            out.line(format!("p.{} = pb_r.utf8(pb_t)?;", ident(&m.name)));
        } else {
            out.line(format!("let pb_t = {};", raw));
            out.line(format!("p.{} = pb_r.text(pb_t, {}, {})?;", ident(&m.name), m.encoding.id(), padded));
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_r.skip_bits({})?;", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_r.skip_bits(pb_r.count({}, {})? * {})?;", self.scope.expr(e), bits, bits));
            }
            Some(Count::Remaining) => out.line("pb_r.skip_bits(pb_r.remaining_bits())?;"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {};", ident(&m.name), read_elem(codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        let n = match count {
            Count::Expr(e) => format!("pb_r.count({}, {})?", self.scope.expr(e), ebits),
            Count::Terminated { term, optional } => {
                out.line(format!("{} = pb_r.read_until(&{}, {})?;", target, byte_list(term), optional));
                return;
            }
            Count::Until(cond) => {
                out.open("while pb_r.remaining_bits() > 0 {");
                out.line(format!("pb_r.at_index({}.len());", target));
                out.line(format!("let pb_last = {};", read_elem(codec, ty)));
                out.line(format!("let pb_stop = {};", self.scope.expr(cond)));
                out.line(format!("{}.push(pb_last);", target));
                out.line("if pb_stop { break; }");
                out.close("}");
                return;
            }
            Count::Remaining => String::new(),
        };
        if ty.is_byte() {
            match count {
                Count::Expr(_) => out.line(format!("{} = pb_r.read_bytes({})?;", target, n)),
                _ => out.line(format!("{} = pb_r.read_bytes(pb_r.remaining_bits() / 8)?;", target)),
            }
            return;
        }
        match count {
            Count::Expr(_) => {
                out.open("{");
                out.line(format!("let pb_n = {};", n));
                out.line(format!("{} = Vec::with_capacity(pb_n);", target));
                out.open("for pb_i in 0..pb_n {");
                out.line("pb_r.at_index(pb_i);");
                out.line(format!("{}.push({});", target, read_elem(codec, ty)));
                out.close("}");
                out.close("}");
            }
            _ => {
                out.open("while pb_r.remaining_bits() > 0 {");
                out.line(format!("pb_r.at_index({}.len());", target));
                out.line(format!("{}.push({});", target, read_elem(codec, ty)));
                out.close("}");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
            _ => format!("pb_r.read_bits({})?", container_width),
        };
        out.line(format!("let pb_c: u64 = {};", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let st = scalar_type(&m.ty);
            let bits = format!("((pb_c >> {}) & 0x{:x})", part.shift, mask(part.width));
            let value = if part.signed {
                format!("pb_sext({}, {}) as {}", bits, part.width, st)
            } else {
                format!("{} as {}", bits, st)
            };
            out.line(format!("p.{} = {};", ident(&m.name), value));
        }
        out.close("}");
    }
}
