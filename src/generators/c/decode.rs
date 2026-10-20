//! C decoder statements. `PB_TRY` jumps to `pb_fail`, which frees the
//! partially decoded value.

use super::expr::store_value;
use super::naming::{C, ident, len_ident, scalar_type};
use super::packet::arm_kind;
use crate::generators::common::union::{C_LOGIC, arm_test};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, StrMode, TExpr, ValueType};

/// Statements that decode one element into the lvalue `lv`.
fn read_elem(out: &mut Out, codec: &Codec, ty: &ValueType, lv: &str) {
    let st = scalar_type(ty);
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("PB_TRY(pb_read_uint(pb_r, {}, {}, &pb_u));", nbytes, C::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("PB_TRY(pb_read_bits(pb_r, {}, &pb_u));", width)),
        Codec::Float { width, endian } => {
            out.line(format!("PB_TRY(pb_read_uint(pb_r, {}, {}, &pb_u));", width / 8, C::little(endian)));
            out.line(format!("{} = pb_f{}_from_bits(pb_u);", lv, width));
            return;
        }
        Codec::Mac => {
            out.line(format!("PB_TRY(pb_read_bytes(pb_r, {}, 6));", lv));
            return;
        }
        Codec::Packet(n) => {
            out.line(format!("PB_TRY({}_decode_from(&{}, pb_r));", n, lv));
            return;
        }
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    }
    match ty {
        ValueType::Int { width, signed: true } => out.line(format!("{} = ({})pb_sext(pb_u, {});", lv, st, width)),
        _ => out.line(format!("{} = ({})pb_u;", lv, st)),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, C>,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode) }
    }

    /// Statements that decode `arm` of union `u` into `place`.
    fn arm(&self, out: &mut Out, u: &str, place: &str, arm: &Arm) {
        out.line(format!("{}.kind = {};", place, arm_kind(u, arm)));
        let target = format!("{}.u.{}", place, ident(&arm.name));
        match (&arm.ty, &arm.codec, &arm.count) {
            (Some(_), _, Some(count)) => {
                out.open("{");
                out.line("size_t pb_n;");
                match count {
                    Count::Expr(e) => out.line(format!("PB_TRY(pb_count(pb_r, {}, 8, &pb_n));", self.scope.expr(e))),
                    Count::Remaining => out.line("pb_n = pb_remaining_bits(pb_r) / 8;"),
                }
                out.line(format!("{}.data = pb_alloc(pb_n, 1);", target));
                out.line(format!("if (!{}.data) {{ pb_rc = PB_ERR_NOMEM; goto pb_fail; }}", target));
                out.line(format!("{}.len = pb_n;", target));
                out.line(format!("PB_TRY(pb_read_bytes(pb_r, {}.data, pb_n));", target));
                out.close("}");
            }
            (Some(ty), Some(codec), None) => read_elem(out, codec, ty, &target),
            _ => {}
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, _message: &str) {
        out.line(format!("PB_TRY({} ? PB_OK : PB_ERR_CONSTRAINT);", self.scope.expr(cond)));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_at(&pb_r->tr, \"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = format!("p->{}", ident(&m.name));
        out.open("{");
        out.line(format!("int64_t pb_sel = {};", self.scope.expr(selector)));
        let tests: Vec<(&Arm, String)> = arms
            .iter()
            .filter(|a| !a.default)
            .map(|a| (a, arm_test(a, arms, "pb_sel", &C_LOGIC).unwrap_or_else(|| "1".into())))
            .collect();
        for (i, (arm, test)) in tests.iter().enumerate() {
            if i > 0 {
                out.pop();
            }
            out.open(format!("{}if {} {{", if i > 0 { "} else " } else { "" }, test));
            self.arm(out, u, &place, arm);
        }
        if !tests.is_empty() {
            out.pop();
            out.open("} else {");
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => self.arm(out, u, &place, arm),
            None => out.line("PB_TRY(PB_ERR_INVALID);"),
        }
        if !tests.is_empty() {
            out.close("}");
        }
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("size_t pb_win{};", id));
        out.line(format!("PB_TRY(pb_push_limit(pb_r, {}, &pb_win{}));", size, id));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("PB_TRY(pb_pop_limit(pb_r, pb_win{}, {}));", id, if exact { 1 } else { 0 }));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("size_t {} = pb_reader_position(pb_r);", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "PB_TRY(((int64_t)p->{} == {}) ? PB_OK : PB_ERR_MISMATCH);",
            ident(&m.name),
            self.scope.expr(value)
        ));
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("PB_TRY(pb_skip_bits(pb_r, pb_pad(pb_reader_position(pb_r) - pb_start, {})));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p->{} = {};", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let p = self.scope.packet;
        let target = format!("&p->{}, &p->{}", ident(&m.name), len_ident(p, m));
        let padded = if *mode == StrMode::Padded { 1 } else { 0 };
        match (mode, array) {
            (StrMode::CString, _) => out.line(format!("PB_TRY(pb_read_ctext(pb_r, {}));", target)),
            (StrMode::Prefixed { prefix, .. }, _) => {
                out.open("{");
                out.line("size_t pb_n;");
                read_elem(out, prefix, &PREFIX_LEN, "pb_u");
                out.line("PB_TRY(pb_count(pb_r, (int64_t)pb_u, 8, &pb_n));");
                out.line(format!("PB_TRY(pb_read_text(pb_r, pb_n, 0, {}));", target));
                out.close("}");
            }
            (_, Some(Count::Expr(e))) => {
                out.open("{");
                out.line("size_t pb_n;");
                out.line(format!("PB_TRY(pb_count(pb_r, {}, 8, &pb_n));", self.scope.expr(e)));
                out.line(format!("PB_TRY(pb_read_text(pb_r, pb_n, {}, {}));", padded, target));
                out.close("}");
            }
            _ => out.line(format!("PB_TRY(pb_read_text(pb_r, pb_remaining_bits(pb_r) / 8, {}, {}));", padded, target)),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("PB_TRY(pb_skip_bits(pb_r, {}));", bits)),
            Some(Count::Expr(e)) => {
                out.open("{");
                out.line("size_t pb_n;");
                out.line(format!("PB_TRY(pb_count(pb_r, {}, {}, &pb_n));", self.scope.expr(e), bits));
                out.line(format!("PB_TRY(pb_skip_bits(pb_r, pb_n * {}));", bits));
                out.close("}");
            }
            Some(Count::Remaining) => out.line("PB_TRY(pb_skip_bits(pb_r, pb_remaining_bits(pb_r)));"),
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        read_elem(out, codec, ty, &format!("p->{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p->{}", ident(&m.name));
        let len = format!("p->{}", len_ident(self.scope.packet, m));
        let ebits = codec.min_elem_bits();
        out.open("{");
        out.line("size_t pb_i = 0;");
        out.line("(void)pb_i;");
        match count {
            Count::Expr(e) => {
                out.line("size_t pb_n;");
                out.line(format!("PB_TRY(pb_count(pb_r, {}, {}, &pb_n));", self.scope.expr(e), ebits));
                out.line(format!("{} = pb_alloc(pb_n, sizeof *{});", target, target));
                out.line(format!("if (!{}) {{ pb_rc = PB_ERR_NOMEM; goto pb_fail; }}", target));
                out.line(format!("{} = pb_n;", len));
                if ty.is_byte() {
                    out.line(format!("PB_TRY(pb_read_bytes(pb_r, {}, pb_n));", target));
                } else {
                    out.open("for (pb_i = 0; pb_i < pb_n; pb_i++) {");
                    out.line("pb_at_index(&pb_r->tr, pb_i);");
                    read_elem(out, codec, ty, &format!("{}[pb_i]", target));
                    out.close("}");
                }
            }
            Count::Remaining => {
                out.line("size_t pb_cap = 0;");
                out.open("for (pb_i = 0; pb_remaining_bits(pb_r) > 0; pb_i++) {");
                out.line(format!("PB_TRY(pb_grow((void **)&{}, &pb_cap, pb_i + 1, sizeof *{}));", target, target));
                out.line(format!("{} = pb_i + 1;", len));
                out.line("pb_at_index(&pb_r->tr, pb_i);");
                read_elem(out, codec, ty, &format!("{}[pb_i]", target));
                out.close("}");
                out.open(format!("if (!{}) {{", target));
                out.line(format!("{} = pb_alloc(0, sizeof *{});", target, target));
                out.line(format!("if (!{}) {{ pb_rc = PB_ERR_NOMEM; goto pb_fail; }}", target));
                out.close("}");
            }
        }
        out.close("}");
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("PB_TRY(pb_read_uint(pb_r, {}, {}, &pb_u));", nbytes, C::little(endian)))
            }
            _ => out.line(format!("PB_TRY(pb_read_bits(pb_r, {}, &pb_u));", container_width)),
        }
        for part in parts {
            let m = self.scope.member(part.member);
            let st = scalar_type(&m.ty);
            let bits = format!("((pb_u >> {}) & UINT64_C(0x{:x}))", part.shift, mask(part.width));
            let v = if part.signed {
                format!("({})pb_sext({}, {})", st, bits, part.width)
            } else {
                format!("({}){}", st, bits)
            };
            out.line(format!("p->{} = {};", ident(&m.name), v));
        }
    }
}
