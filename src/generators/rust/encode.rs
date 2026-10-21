//! Rust encoder statements.

use super::decode::{byte_list, call_args};
use super::expr::store_value;
use super::naming::{Rust, ident, scalar_type};
use crate::generators::common::union::{C_LOGIC, arm_test, mismatch_message, uses_selector, variant_name};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// Statements that write one element held in `v`.
fn write_elem(scope: &Scope<'_, Rust>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("pb_w.check_i({} as i64, {})?;", v, width));
        } else {
            out.line(format!("pb_w.check_u({} as u64, {})?;", v, width));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pb_w.write_uint({} as u64, {}, {});", v, nbytes, Rust::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pb_w.write_bits({} as u64, {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("pb_w.write_uint({}.to_bits() as u64, 4, {});", v, Rust::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("pb_w.write_uint({}.to_bits(), 8, {});", v, Rust::little(endian)))
        }
        Codec::Mac => out.line(format!("pb_w.write_bytes(&{});", v)),
        Codec::Varint(k) => out.line(format!("pb_w.write_varint({}, {} as u64)?;", k.id(), v)),
        Codec::Packet(r) => out.line(format!("{}.encode_to(pb_w{})?;", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Rust>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if !{} {{ return Err(pb_w.error(PbErrorKind::Constraint, {}.into())); }}",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_w.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        out.open("{");
        if uses_selector(arms) {
            out.line(format!("let pb_sel: i64 = {};", self.scope.expr(selector)));
        }
        out.open(format!("match &p.{} {{", ident(&m.name)));
        for arm in arms {
            let v = variant_name(arm);
            let pat = if arm.ty.is_some() { format!("{}::{}(pb_v)", u, v) } else { format!("{}::{}", u, v) };
            out.open(format!("{} => {{", pat));
            if let Some(test) = arm_test(arm, arms, "pb_sel", &C_LOGIC) {
                out.line(format!(
                    "if !{} {{ return Err(pb_w.error(PbErrorKind::Mismatch, {}.into())); }}",
                    test,
                    string_literal(&mismatch_message(&m.name, arm))
                ));
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pb_w.check_len(pb_v.len(), {})?;", self.scope.expr(e)));
                    }
                    out.line("pb_w.write_bytes(pb_v);");
                }
                (Some(ty), Some(codec), None) => {
                    let v = if matches!(codec, Codec::Packet(_)) { "pb_v" } else { "(*pb_v)" };
                    write_elem(&self.scope, out, codec, ty, v);
                }
                _ => {}
            }
            out.close("}");
        }
        out.close("}");
        out.close("}");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("let mut pb_s = pb_w.sub({}, {}, {})?;", from, self.scope.expr(offset), root));
        out.line(format!("p.{}.encode_to(&mut pb_s{})?;", ident(&m.name), call_args(&self.scope, target)));
        out.line("pb_w.place(pb_s);");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("let pb_win{} = pb_w.position_bits();", id));
            out.line(format!("let pb_wsz{}: i64 = {};", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pb_w.end_window(pb_win{}, pb_wsz{}, {})?;", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("let {} = pb_w.position_bits();", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("let pbc_{}: i64 = {};", m.name, self.scope.expr(value)));
        } else {
            out.line(format!(
                "let pbc_{}: {} = {};",
                m.name,
                scalar_type(&m.ty),
                store_value(self.scope.expr(value), &m.ty)
            ));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("pb_w.check_i({}, {})?;", v, width));
            } else {
                out.line(format!("pb_w.check_u({} as u64, {})?;", v, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pb_w.write_uint({} as u64, {}, {});", v, nbytes, Rust::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => out.line(format!(
                "pb_w.patch_uint({}, {} as u64, {}, {});",
                mark_var(at),
                v,
                nbytes,
                Rust::little(endian)
            )),
            (Codec::Bits { width }, None) => out.line(format!("pb_w.write_bits({} as u64, {});", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pb_w.patch_bits({}, {} as u64, {});", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("pb_w.write_varint({}, {} as u64)?;", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_w.write_zero_bits(pb_pad(pb_w.position_bits() - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("{");
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("let pb_b = p.{}.as_bytes();", ident(&m.name)));
        } else {
            out.line(format!("let pb_e = pb_w.text(&p.{}, {})?;", ident(&m.name), m.encoding.id()));
            out.line("let pb_b = pb_e.as_slice();");
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pb_w.check_no_nul(pb_b)?;");
                out.line("pb_w.write_bytes(pb_b);");
                out.line("pb_w.write_bytes(&[0]);");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("pb_w.check_no_term(pb_b, &{})?;", byte_list(term)));
                out.line("pb_w.write_bytes(pb_b);");
                out.line(format!("pb_w.write_bytes(&{});", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pb_w.check_u(pb_b.len() as u64, {})?;", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "pb_b.len()");
                out.line("pb_w.write_bytes(pb_b);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("let pb_n = {};", self.scope.expr(e)));
                out.line("pb_w.check_fits(pb_b.len(), pb_n)?;");
                out.line("pb_w.write_bytes(pb_b);");
                out.line("pb_w.write_zero_bits((pb_n as usize - pb_b.len()) * 8);");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pb_w.check_len(pb_b.len(), {})?;", self.scope.expr(e)));
                out.line("pb_w.write_bytes(pb_b);");
            }
            _ => out.line("pb_w.write_bytes(pb_b);"),
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_w.write_zero_bits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_w.write_zero_bits(({}).max(0) as usize * {});", self.scope.expr(e), bits))
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &format!("p.{}", ident(&m.name)));
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if {} {{", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("}");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("pb_w.adopt_version(p.{} as i64, {}, {})?;", ident(&m.name), min, latest));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pb_w.check_len({}.len(), {})?;", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("pb_w.check_no_term(&{}, &{})?;", place, byte_list(term)));
            out.line(format!("pb_w.write_bytes(&{});", place));
            out.line(format!("pb_w.write_bytes(&{});", byte_list(term)));
            return;
        }
        if ty.is_byte() {
            out.line(format!("pb_w.write_bytes(&{});", place));
        } else {
            out.open(format!("for (pb_i, pb_v) in {}.iter().enumerate() {{", place));
            out.line("pb_w.at_index(pb_i);");
            let v = match codec {
                Codec::Packet(_) => "pb_v",
                _ => "*pb_v",
            };
            write_elem(&self.scope, out, codec, ty, &format!("({})", v));
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("let mut pb_c: u64 = 0;");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", ident(&m.name));
            if part.signed {
                out.line(format!("pb_w.check_i({} as i64, {})?;", place, part.width));
            } else {
                out.line(format!("pb_w.check_u({} as u64, {})?;", place, part.width));
            }
            out.line(format!("pb_c |= (({} as u64) & 0x{:x}) << {};", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pb_w.write_uint(pb_c, {}, {});", nbytes, Rust::little(endian)))
            }
            _ => out.line(format!("pb_w.write_bits(pb_c, {});", container_width)),
        }
        out.close("}");
    }
}
