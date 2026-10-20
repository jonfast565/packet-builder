//! C encoder statements. `PB_CHECK` returns the error code on failure.

use super::decode::term_args;
use super::expr::store_value;
use super::naming::{C, ident, len_ident, scalar_type};
use super::packet::arm_kind;
use crate::generators::common::union::{C_LOGIC, arm_test, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, TextEncoding, ValueType};

fn write_elem(out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("PB_CHECK(pb_check_i((int64_t){}, {}));", v, width));
        } else {
            out.line(format!("PB_CHECK(pb_check_u((uint64_t){}, {}));", v, width));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("PB_CHECK(pb_write_uint(pb_w, (uint64_t){}, {}, {}));", v, nbytes, C::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("PB_CHECK(pb_write_bits(pb_w, (uint64_t){}, {}));", v, width)),
        Codec::Float { width, endian } => out.line(format!(
            "PB_CHECK(pb_write_uint(pb_w, pb_f{}_bits({}), {}, {}));",
            width,
            v,
            width / 8,
            C::little(endian)
        )),
        Codec::Mac => out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}, 6));", v)),
        Codec::Varint(k) => out.line(format!("PB_CHECK(pb_write_varint(pb_w, {}, (uint64_t){}));", k.id(), v)),
        Codec::Packet(n) => out.line(format!("PB_CHECK({}_encode_to(&{}, pb_w));", n, v)),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, C>,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode) }
    }

    fn len(&self, m: &Member) -> String {
        format!("p->{}", len_ident(self.scope.packet, m))
    }
}

impl Encoder<'_> {
    /// A string in an encoding other than UTF-8: `pb_sz` is its encoded size.
    fn encoded_string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let s = format!("p->{}", ident(&m.name));
        let len = self.len(m);
        let write = format!("PB_CHECK(pb_write_text(pb_w, {}, {}, {}));", s, len, m.encoding.id());
        out.open("{");
        out.line("size_t pb_sz;");
        out.line(format!("PB_CHECK(pb_text_size({}, {}, {}, &pb_sz));", s, len, m.encoding.id()));
        match (mode, array) {
            (StrMode::CString | StrMode::Terminated { .. }, _) => {
                let term = match mode {
                    StrMode::Terminated { term, .. } => term.clone(),
                    _ => vec![0],
                };
                out.line("size_t pb_from = pb_writer_position(pb_w);");
                out.line(write);
                out.line(format!("PB_CHECK(pb_check_no_term(pb_w, pb_from, {}));", term_args(&term)));
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}));", term_args(&term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("PB_CHECK(pb_check_u((uint64_t)pb_sz, {}));", width));
                write_elem(out, prefix, &PREFIX_LEN, "pb_sz");
                out.line(write);
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.line(format!("int64_t pb_n = {};", self.scope.expr(e)));
                out.line("PB_CHECK(pb_check_fits(pb_sz, pb_n));");
                out.line(write);
                out.line("PB_CHECK(pb_write_zero_bits(pb_w, (pb_n - (int64_t)pb_sz) * 8));");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("PB_CHECK(pb_check_len(pb_sz, {}));", self.scope.expr(e)));
                out.line(write);
            }
            _ => out.line(write),
        }
        out.close("}");
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, _message: &str) {
        out.line(format!("PB_CHECK({} ? PB_OK : PB_ERR_CONSTRAINT);", self.scope.expr(cond)));
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_at(&pb_w->tr, \"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = format!("p->{}", ident(&m.name));
        out.open("{");
        if uses_selector(arms) {
            out.line(format!("int64_t pb_sel = {};", self.scope.expr(selector)));
        }
        out.open(format!("switch ({}.kind) {{", place));
        for arm in arms {
            out.open(format!("case {}:", arm_kind(u, arm)));
            if let Some(test) = arm_test(arm, arms, "pb_sel", &C_LOGIC) {
                out.line(format!("PB_CHECK({} ? PB_OK : PB_ERR_MISMATCH);", test));
            }
            let target = format!("{}.u.{}", place, ident(&arm.name));
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("PB_CHECK(pb_check_len({}.len, {}));", target, self.scope.expr(e)));
                    }
                    out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}.data, {}.len));", target, target));
                }
                (Some(ty), Some(codec), None) => write_elem(out, codec, ty, &target),
                _ => {}
            }
            out.line("break;");
            out.pop();
        }
        out.line("default:");
        out.line("    PB_CHECK(PB_ERR_INVALID);");
        out.close("}");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            out.line(format!("size_t pb_win{} = pb_writer_position(pb_w);", id));
            out.line(format!("int64_t pb_wsz{} = {};", id, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!(
                "PB_CHECK(pb_end_window(pb_w, pb_win{}, pb_wsz{}, {}));",
                id,
                id,
                if exact { 1 } else { 0 }
            ));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("size_t {} = pb_writer_position(pb_w);", mark_var(mark)));
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        if m.is_derived() {
            out.line(format!("int64_t pbc_{} = {};", m.name, self.scope.expr(value)));
        } else {
            out.line(format!(
                "{} pbc_{} = {};",
                scalar_type(&m.ty),
                m.name,
                store_value(self.scope.expr(value), &m.ty)
            ));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("PB_CHECK(pb_check_i({}, {}));", v, width));
            } else {
                out.line(format!("PB_CHECK(pb_check_u((uint64_t){}, {}));", v, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("PB_CHECK(pb_write_uint(pb_w, (uint64_t){}, {}, {}));", v, nbytes, C::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => out.line(format!(
                "pb_patch_uint(pb_w, {}, (uint64_t){}, {}, {});",
                mark_var(at),
                v,
                nbytes,
                C::little(endian)
            )),
            (Codec::Bits { width }, None) => {
                out.line(format!("PB_CHECK(pb_write_bits(pb_w, (uint64_t){}, {}));", v, width))
            }
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("pb_patch_bits(pb_w, {}, (uint64_t){}, {});", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => {
                out.line(format!("PB_CHECK(pb_write_varint(pb_w, {}, (uint64_t){}));", k.id(), v))
            }
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!(
            "PB_CHECK(pb_write_zero_bits(pb_w, (int64_t)pb_pad(pb_writer_position(pb_w) - pb_start, {})));",
            bytes * 8
        ))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let s = format!("p->{}", ident(&m.name));
        let len = self.len(m);
        let allow_nul = if matches!(mode, StrMode::CString) { 0 } else { 1 };
        out.line(format!("PB_CHECK(pb_check_text({}, {}, {}));", s, len, allow_nul));
        if m.encoding != TextEncoding::Utf8 {
            self.encoded_string(out, m, mode, array);
            return;
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len));
                out.line("PB_CHECK(pb_write_bits(pb_w, 0, 8));");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.open("{");
                out.line("size_t pb_from = pb_writer_position(pb_w);");
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len));
                out.line(format!("PB_CHECK(pb_check_no_term(pb_w, pb_from, {}));", term_args(term)));
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}));", term_args(term)));
                out.close("}");
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("PB_CHECK(pb_check_u((uint64_t){}, {}));", len, width));
                write_elem(out, prefix, &PREFIX_LEN, &len);
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len));
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                out.open("{");
                out.line(format!("int64_t pb_n = {};", self.scope.expr(e)));
                out.line(format!("PB_CHECK(pb_check_fits({}, pb_n));", len));
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len));
                out.line(format!("PB_CHECK(pb_write_zero_bits(pb_w, (pb_n - (int64_t){}) * 8));", len));
                out.close("}");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("PB_CHECK(pb_check_len({}, {}));", len, self.scope.expr(e)));
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len));
            }
            _ => out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len)),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("PB_CHECK(pb_write_zero_bits(pb_w, {}));", bits)),
            Some(Count::Expr(e)) => out.line(format!(
                "PB_CHECK(pb_write_zero_bits(pb_w, pb_mul(pb_max_i({}, 0), {})));",
                self.scope.expr(e),
                bits
            )),
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &format!("p->{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p->{}", ident(&m.name));
        let len = self.len(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("PB_CHECK(pb_check_len({}, {}));", len, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.open("{");
            out.line("size_t pb_from = pb_writer_position(pb_w);");
            out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}, {}));", place, len));
            out.line(format!("PB_CHECK(pb_check_no_term(pb_w, pb_from, {}));", term_args(term)));
            out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}));", term_args(term)));
            out.close("}");
        } else if ty.is_byte() {
            out.line(format!("PB_CHECK(pb_write_bytes(pb_w, {}, {}));", place, len));
        } else {
            out.open("{");
            out.line("size_t pb_i;");
            out.open(format!("for (pb_i = 0; pb_i < {}; pb_i++) {{", len));
            out.line("pb_at_index(&pb_w->tr, pb_i);");
            write_elem(out, codec, ty, &format!("{}[pb_i]", place));
            out.close("}");
            out.close("}");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line("uint64_t pb_c = 0;");
        for part in parts {
            let m = self.scope.member(part.member);
            let place = format!("p->{}", ident(&m.name));
            if part.signed {
                out.line(format!("PB_CHECK(pb_check_i((int64_t){}, {}));", place, part.width));
            } else {
                out.line(format!("PB_CHECK(pb_check_u((uint64_t){}, {}));", place, part.width));
            }
            out.line(format!("pb_c |= ((uint64_t){} & UINT64_C(0x{:x})) << {};", place, mask(part.width), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("PB_CHECK(pb_write_uint(pb_w, pb_c, {}, {}));", nbytes, C::little(endian)))
            }
            _ => out.line(format!("PB_CHECK(pb_write_bits(pb_w, pb_c, {}));", container_width)),
        }
        out.close("}");
    }
}
