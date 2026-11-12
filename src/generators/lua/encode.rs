//! Lua encoder statements (the writer is `w`, the value `p`).

use super::expr::call_args;
use super::naming::{Lua, class};
use crate::generators::common::lua::{byte_string, store_value};
use crate::generators::common::union::{PY_LOGIC, arm_test, mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// Range-check and write `v`, one element of type `ty`.
fn write_elem(scope: &Scope<'_, Lua>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    match ty {
        ValueType::Int { width, signed: true } => out.line(format!("w:check_i({}, {})", v, width)),
        ValueType::Int { width, signed: false } => out.line(format!("w:check_u({}, {})", v, width)),
        ValueType::Mac => out.line(format!("w:check_len(#{}, 6)", v)),
        _ => {}
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("w:write_uint({}, {}, {})", v, nbytes, Lua::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("w:write_bits({}, {})", v, width)),
        Codec::Float { width, endian } => out.line(format!("w:write_float({}, {}, {})", v, width, Lua::little(endian))),
        Codec::Mac => out.line(format!("w:write_bytes({})", v)),
        Codec::Varint(k) => out.line(format!("w:write_varint({}, {})", k.id(), v)),
        Codec::Packet(r) => out.line(format!("{}.encode_to({}, w{})", class(&r.name), v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

/// The locals `pbc_<name>` an encoder computes (`Scope::place` reads them).
pub fn encode_locals(p: &Packet) -> Vec<String> {
    p.members
        .iter()
        .filter(|m| (m.is_calculated() && !m.is_decode_only()) || m.is_derived())
        .map(|m| format!("pbc_{}", m.name))
        .collect()
}

pub struct Encoder<'a> {
    scope: Scope<'a, Lua>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }

    fn place(&self, m: &Member) -> String {
        self.scope.field(m)
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if not {} then w:fail(\"constraint\", {}) end",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("w:at({})", string_literal(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let place = self.place(m);
        if uses_selector(arms) {
            out.line(format!("pb_sel = {}", self.scope.expr(selector)));
        }
        out.line(format!("pb_v = {}.value", place));
        for (i, arm) in arms.iter().enumerate() {
            if i > 0 {
                out.pop();
            }
            out.open(format!(
                "{} {}.kind == {} then",
                if i == 0 { "if" } else { "elseif" },
                place,
                string_literal(&arm.name)
            ));
            if let Some(test) = arm_test(arm, arms, "pb_sel", &PY_LOGIC) {
                out.line(format!(
                    "if not {} then w:fail(\"mismatch\", {}) end",
                    test,
                    string_literal(&mismatch_message(&m.name, arm))
                ));
            }
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("w:check_len(#pb_v, {})", self.scope.expr(e)));
                    }
                    out.line("w:write_bytes(pb_v)");
                }
                (Some(ty), Some(codec), None) => write_elem(&self.scope, out, codec, ty, "pb_v"),
                _ => {}
            }
        }
        out.pop();
        out.open("else");
        out.line(format!("w:fail(\"invalid\", {})", string_literal(&format!("`{}` holds no known arm", m.name))));
        out.close("end");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("local pb_win{} = w.pos", id));
            out.line(format!("local pb_wsz{} = {}", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("w:end_window(pb_win{}, pb_wsz{}, {})", id, id, exact));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("local {} = w.pos", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = w.pos", mark_var(mark)));
    }

    /// `pbc_<name>` is declared at the top of `encode_to` (`encode_locals`).
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
            let check = if *signed { "check_i" } else { "check_u" };
            out.line(format!("w:{}({}, {})", check, v, width));
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("w:write_uint({}, {}, {})", v, nbytes, Lua::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("w:patch_uint({}, {}, {}, {})", mark_var(at), v, nbytes, Lua::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("w:write_bits({}, {})", v, width)),
            (Codec::Bits { width }, Some(at)) => out.line(format!("w:patch_bits({}, {}, {})", mark_var(at), v, width)),
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("w:write_varint({}, {})", k.id(), v)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("pb_s = w:sub({}, {}, {})", from, self.scope.expr(offset), root));
        out.line(format!(
            "{}.encode_to({}, pb_s{})",
            class(&target.name),
            self.place(m),
            call_args(&self.scope, target)
        ));
        out.line("w:place(pb_s)");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("w:write_zero_bits(pb_pad(w.pos - pb_start, {}))", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let place = self.place(m);
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("pb_b = w:utf8_bytes({})", place));
        } else {
            out.line(format!("pb_b = w:text_bytes({}, {})", place, m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("w:check_no_nul(pb_b)");
                out.line("w:write_bytes(pb_b .. \"\\0\")");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("w:check_no_term(pb_b, {})", byte_string(term)));
                out.line(format!("w:write_bytes(pb_b .. {})", byte_string(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("w:check_u(#pb_b, {})", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "#pb_b");
                out.line("w:write_bytes(pb_b)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("pb_n = {}", self.scope.expr(e)));
                out.line("w:check_fits(#pb_b, pb_n)");
                out.line("w:write_bytes(pb_b .. string.rep(\"\\0\", pb_n - #pb_b))");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("w:check_len(#pb_b, {})", self.scope.expr(e)));
                out.line("w:write_bytes(pb_b)");
            }
            _ => out.line("w:write_bytes(pb_b)"),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("w:write_zero_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("w:write_zero_bits(math.max({}, 0) * {})", self.scope.expr(e), bits))
            }
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if {} then", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("end");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("w:adopt_version({}, {}, {})", self.place(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &self.place(m));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.place(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("w:check_len(#{}, {})", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("w:check_no_term({}, {})", place, byte_string(term)));
            out.line(format!("w:write_bytes(pb_chars({}) .. {})", place, byte_string(term)));
        } else if ty.is_byte() {
            out.line(format!("w:write_bytes({})", place));
        } else {
            out.open(format!("for pb_i, pb_e in ipairs({}) do", place));
            out.line("w:at_index(pb_i - 1)");
            write_elem(&self.scope, out, codec, ty, "pb_e");
            out.close("end");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.line("pb_c = 0");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = self.place(m);
            let check = if part.signed { "check_i" } else { "check_u" };
            out.line(format!("w:{}({}, {})", check, place, part.width));
            out.line(format!("pb_c = pb_c | (({} & 0x{:x}) << {})", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("w:write_uint(pb_c, {}, {})", nbytes, Lua::little(endian)))
            }
            _ => out.line(format!("w:write_bits(pb_c, {})", container_width)),
        }
    }
}
