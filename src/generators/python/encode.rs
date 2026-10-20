//! Python encoder statements.

use super::decode::byte_list;
use super::expr::store_value;
use super::naming::{Python, float_format, ident};
use crate::generators::common::union::{PY_LOGIC, arm_test, mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, TextEncoding, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    match ty {
        ValueType::Int { width, signed: true } => out.line(format!("pb_w.check_i({}, {})", v, width)),
        ValueType::Int { width, signed: false } => out.line(format!("pb_w.check_u({}, {})", v, width)),
        ValueType::Mac => out.line(format!("pb_w.check_len(len({}), 6)", v)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("pb_w.write_uint({}, {}, {})", v, nbytes, Python::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("pb_w.write_bits({}, {})", v, width)),
        Codec::Float { width, endian } => {
            out.line(format!("pb_w.write_bytes(struct.pack(\"{}\", {}))", float_format(*width, endian), v));
        }
        Codec::Mac => out.line(format!("pb_w.write_bytes(bytes({}))", v)),
        Codec::Varint(k) => out.line(format!("pb_w.write_varint({}, {})", k.id(), v)),
        Codec::Packet(_) => out.line(format!("{}.encode_to(pb_w)", v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Python>,
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
        out.open(format!("if not {}:", self.scope.expr(cond)));
        out.line(format!("raise pb_w.error(PbError.CONSTRAINT, {})", string_literal(message)));
        out.pop();
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_w.at(\"{}\")", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let place = format!("p.{}", ident(&m.name));
        if uses_selector(arms) {
            out.line(format!("pb_sel = {}", self.scope.expr(selector)));
        }
        out.line(format!("pb_v = {}.value", place));
        for (i, arm) in arms.iter().enumerate() {
            out.open(format!("{} {}.kind == \"{}\":", if i == 0 { "if" } else { "elif" }, place, arm.name));
            if let Some(test) = arm_test(arm, arms, "pb_sel", &PY_LOGIC) {
                out.open(format!("if not {}:", test));
                out.line(format!(
                    "raise pb_w.error(PbError.MISMATCH, {})",
                    string_literal(&mismatch_message(&m.name, arm))
                ));
                out.pop();
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("pb_w.check_len(len(pb_v), {})", self.scope.expr(e)));
                    }
                    out.line("pb_w.write_bytes(bytes(pb_v))");
                }
                (Some(ty), Some(codec), None) => write_elem(out, codec, ty, "pb_v"),
                _ => out.line("pass"),
            }
            out.pop();
        }
        out.open("else:");
        out.line(format!(
            "raise pb_w.error(PbError.INVALID, {})",
            string_literal(&format!("`{}` holds no known arm", m.name))
        ));
        out.pop();
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("pb_win{} = pb_w.position_bits()", id));
            out.line(format!("pb_wsz{} = {}", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("pb_w.end_window(pb_win{}, pb_wsz{}, {})", id, id, if exact { "True" } else { "False" }));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pb_w.position_bits()", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("pbc_{} = {}", m.name, self.scope.expr(value)));
        } else {
            out.line(format!("pbc_{} = {}", m.name, store_value(self.scope.expr(value), &m.ty)));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("pb_w.check_i({}, {})", v, width));
            } else {
                out.line(format!("pb_w.check_u({}, {})", v, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("pb_w.write_uint({}, {}, {})", v, nbytes, Python::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("pb_w.patch_uint({}, {}, {}, {})", mark_var(at), v, nbytes, Python::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("pb_w.write_bits({}, {})", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pb_w.patch_bits({}, {}, {})", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("pb_w.write_varint({}, {})", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_w.write_zero_bits(_pb_pad(pb_w.position_bits() - pb_start, {}))", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("pb_b = pb_w.utf8_bytes(p.{})", ident(&m.name)));
        } else {
            out.line(format!("pb_b = pb_w.text_bytes(p.{}, {})", ident(&m.name), m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("pb_w.check_no_nul(pb_b)");
                out.line("pb_w.write_bytes(pb_b + b\"\\0\")");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("pb_w.check_no_term(pb_b, {})", byte_list(term)));
                out.line(format!("pb_w.write_bytes(pb_b + {})", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("pb_w.check_u(len(pb_b), {})", width));
                write_elem(out, prefix, &PREFIX_LEN, "len(pb_b)");
                out.line("pb_w.write_bytes(pb_b)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("pb_n = {}", self.scope.expr(e)));
                out.line("pb_w.check_fits(len(pb_b), pb_n)");
                out.line("pb_w.write_bytes(pb_b + bytes(pb_n - len(pb_b)))");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("pb_w.check_len(len(pb_b), {})", self.scope.expr(e)));
                out.line("pb_w.write_bytes(pb_b)");
            }
            _ => out.line("pb_w.write_bytes(pb_b)"),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_w.write_zero_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_w.write_zero_bits(max({}, 0) * {})", self.scope.expr(e), bits))
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &format!("p.{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p.{}", ident(&m.name));
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("pb_w.check_len(len({}), {})", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("pb_w.check_no_term({}, {})", place, byte_list(term)));
            out.line(format!("pb_w.write_bytes(bytes({}) + {})", place, byte_list(term)));
        } else if ty.is_byte() {
            out.line(format!("pb_w.write_bytes(bytes({}))", place));
        } else {
            out.open(format!("for pb_i, pb_v in enumerate({}):", place));
            out.line("pb_w.at_index(pb_i)");
            write_elem(out, codec, ty, "pb_v");
            out.pop();
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.line("pb_c = 0");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p.{}", ident(&m.name));
            if part.signed {
                out.line(format!("pb_w.check_i({}, {})", place, part.width));
            } else {
                out.line(format!("pb_w.check_u({}, {})", place, part.width));
            }
            out.line(format!("pb_c |= ({} & 0x{:x}) << {}", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("pb_w.write_uint(pb_c, {}, {})", nbytes, Python::little(endian)))
            }
            _ => out.line(format!("pb_w.write_bits(pb_c, {})", container_width)),
        }
    }
}
