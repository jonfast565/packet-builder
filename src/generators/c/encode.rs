//! C encoder statements. `PB_CHECK` returns the error code on failure.

use super::naming::{C, ident, len_ident};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mask};
use crate::ir::{BitPart, Codec, Count, Member, Packet, StrMode, TExpr, ValueType};

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
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("PB_CHECK(pb_write_bytes(pb_w, (const uint8_t *){}, {}));", s, len));
                out.line("PB_CHECK(pb_write_bits(pb_w, 0, 8));");
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
            (_, Some(Count::Expr(e))) => {
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
            Some(Count::Remaining) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(out, codec, ty, &format!("p->{}", ident(&m.name)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = format!("p->{}", ident(&m.name));
        let len = self.len(m);
        if let Count::Expr(e) = count {
            out.line(format!("PB_CHECK(pb_check_len({}, {}));", len, self.scope.expr(e)));
        }
        if ty.is_byte() {
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
