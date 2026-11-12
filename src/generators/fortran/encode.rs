//! Fortran encoder statements. Errors are recorded on the writer
//! (`pb_w%e`); every statement that may fail is followed by a return.

use super::decode::{arm_test, call_args, fail};
use super::expr::{int64, store_value};
use super::locals::Locals;
use super::naming::{Fortran, arm_component, byte_list, f_string, int_kind, kind_bits, scalar_type, type_name};
use crate::generators::common::union::{mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, ValueType};

/// Return when the writer holds an error.
pub const W_FAILED: &str = "if (pb_w%e%kind /= PB_OK) return";

/// Fail unless int64 expression `v` fits `width` bits.
fn check_bits(out: &mut Out, v: &str, width: u32, signed: bool) {
    if width >= 64 {
        return;
    }
    let f = if signed { "pb_check_i" } else { "pb_check_u" };
    out.line(format!("call {}(pb_w, {}, {})", f, v, width));
    out.line(W_FAILED);
}

/// Fail unless value `v` of `ty` fits its width: Fortran stores it in a
/// wider kind (unsigned values always, since they have no unsigned kind).
fn range_check(out: &mut Out, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && (!*signed || *width != kind_bits(int_kind(*width, *signed)))
    {
        check_bits(out, &format!("int({}, int64)", v), *width, *signed);
    }
}

/// Write value `v` of `ty` with `codec`.
fn write_elem(scope: &Scope<'_, Fortran>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    range_check(out, ty, v);
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("call pb_write_uint(pb_w, int({}, int64), {}, {})", v, nbytes, Fortran::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("call pb_write_bits(pb_w, int({}, int64), {})", v, width)),
        Codec::Float { width: 32, endian } => out.line(format!(
            "call pb_write_uint(pb_w, pb_f32_bits(real({}, real32)), 4, {})",
            v,
            Fortran::little(endian)
        )),
        Codec::Float { endian, .. } => out.line(format!(
            "call pb_write_uint(pb_w, pb_f64_bits(real({}, real64)), 8, {})",
            v,
            Fortran::little(endian)
        )),
        Codec::Mac => out.line(format!("call pb_write_bytes(pb_w, {})", v)),
        Codec::Varint(k) => {
            out.line(format!("call pb_write_varint(pb_w, {}, int({}, int64))", k.id(), v));
            out.line(W_FAILED);
        }
        Codec::Packet(r) => {
            out.line(format!("call {}_encode_to({}, pb_w{})", type_name(&r.name), v, call_args(scope, r)));
            out.line(W_FAILED);
        }
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

/// Write packet `v` (allocatable): its default value while it is not
/// allocated.
fn write_alloc_packet(scope: &Scope<'_, Fortran>, locals: &Locals, out: &mut Out, r: &PacketRef, v: &str, w: &str) {
    let t = type_name(&r.name);
    let def = locals.var(format!("pbdef_{}", t), &format!("type({})", t));
    let args = call_args(scope, r);
    out.open(format!("if (allocated({})) then", v));
    out.line(format!("call {}_encode_to({}, {}{})", t, v, w, args));
    out.close("else");
    out.push();
    out.line(format!("call {}_encode_to({}, {}{})", t, def, w, args));
    out.close("end if");
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Fortran>,
    pub locals: &'a Locals,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet, locals: &'a Locals) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode), locals }
    }

    fn arm_value(&self, out: &mut Out, place: &str, arm: &Arm) {
        let value = format!("{}%{}", place, arm_component(arm));
        match (&arm.ty, &arm.codec, &arm.count) {
            (Some(_), _, Some(count)) => {
                if let Count::Expr(e) = count
                    && !self.packet().depends_on_wire(e)
                {
                    out.line(format!("call pb_check_len(pb_w, pb_size({}), {})", value, self.scope.expr(e)));
                    out.line(W_FAILED);
                }
                out.line(format!("call pb_write_buf(pb_w, {})", value));
            }
            (Some(_), Some(Codec::Packet(r)), None) => {
                write_alloc_packet(&self.scope, self.locals, out, r, &value, "pb_w");
                out.line(W_FAILED);
            }
            (Some(ty), Some(codec), None) => write_elem(&self.scope, out, codec, ty, &value),
            _ => {}
        }
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.open(format!("if (.not. {}) then", self.scope.expr(cond)));
        fail(out, "pb_w", "PB_CONSTRAINT", &f_string(message));
        out.close("end if");
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("call pb_at(pb_w, {})", f_string(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let place = self.scope.field(m);
        if uses_selector(arms) {
            let sel = self.locals.var("pbsel", "integer(int64)");
            out.line(format!("{} = {}", sel, self.scope.expr(selector)));
        }
        out.open(format!("select case ({}%pb_arm)", place));
        for (i, arm) in arms.iter().enumerate() {
            out.line(format!("case ({})", i + 1));
            out.push();
            if let Some(test) = arm_test(arm, arms, "pbsel") {
                out.open(format!("if (.not. {}) then", test));
                fail(out, "pb_w", "PB_MISMATCH", &f_string(&mismatch_message(&m.name, arm)));
                out.close("end if");
            }
            self.arm_value(out, &place, arm);
            out.pop();
        }
        out.line("case default");
        out.push();
        fail(out, "pb_w", "PB_INVALID", &f_string(&format!("`{}` holds no known arm", m.name)));
        out.pop();
        out.close("end select");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0_int64" } else { "pb_start" };
        let n = self.locals.var("pbn", "integer(int64)");
        let s = self.locals.var("pbs", "type(pb_writer)");
        out.line(format!("{} = {}", n, self.scope.expr(offset)));
        out.line(format!("call pb_sub_writer(pb_w, {}, pbn, {}, {})", from, Fortran::flag(root), s));
        out.line(W_FAILED);
        write_alloc_packet(&self.scope, self.locals, out, target, &self.scope.field(m), "pbs");
        out.line("call pb_place(pb_w, pbs)");
        out.line(W_FAILED);
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            let w = self.locals.var(format!("pb_win{}", id), "integer(int64)");
            let z = self.locals.var(format!("pb_wsz{}", id), "integer(int64)");
            out.line(format!("{} = pb_w%pos", w));
            out.line(format!("{} = {}", z, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("call pb_end_window(pb_w, pb_win{}, pb_wsz{}, {})", id, id, Fortran::flag(exact)));
            out.line(W_FAILED);
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals.var(mark_var(mark), "integer(int64)");
        out.line(format!("{} = pb_w%pos", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        let name = format!("pbc_{}", m.name);
        if m.is_derived() {
            self.locals.var(&name, "integer(int64)");
            out.line(format!("{} = {}", name, self.scope.expr(value)));
        } else {
            self.locals.var(&name, &scalar_type(&m.ty));
            out.line(format!("{} = {}", name, store_value(self.scope.expr(value), &m.ty)));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = format!("pbc_{}", m.name);
        if let ValueType::Int { width, signed } = &m.ty {
            check_bits(out, &v, *width, *signed);
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("call pb_write_uint(pb_w, {}, {}, {})", v, nbytes, Fortran::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => out.line(format!(
                "call pb_patch_uint(pb_w, {}, {}, {}, {})",
                mark_var(at),
                v,
                nbytes,
                Fortran::little(endian)
            )),
            (Codec::Bits { width }, None) => out.line(format!("call pb_write_bits(pb_w, {}, {})", v, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("call pb_patch_bits(pb_w, {}, {}, {})", mark_var(at), v, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => {
                out.line(format!("call pb_write_varint(pb_w, {}, {})", k.id(), v));
                out.line(W_FAILED);
            }
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("call pb_write_zero_bits(pb_w, pb_pad(pb_w%pos - pb_start, {}))", int64(bytes as i64 * 8)))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let b = self.locals.array("pbb", "integer(int8)");
        out.line(format!("call pb_text_bytes(pb_w, {}, {}, {})", self.scope.field(m), m.encoding.id(), b));
        out.line(W_FAILED);
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("call pb_check_no_nul(pb_w, pbb)");
                out.line(W_FAILED);
                out.line("call pb_write_buf(pb_w, pbb)");
                out.line("call pb_write_uint(pb_w, 0_int64, 1, .false.)");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("call pb_check_no_term(pb_w, pbb, {})", byte_list(term)));
                out.line(W_FAILED);
                out.line("call pb_write_buf(pb_w, pbb)");
                out.line(format!("call pb_write_bytes(pb_w, {})", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                check_bits(out, "pb_size(pbb)", *width, false);
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "pb_size(pbb)");
                out.line("call pb_write_buf(pb_w, pbb)");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                let n = self.locals.var("pbn", "integer(int64)");
                out.line(format!("{} = {}", n, self.scope.expr(e)));
                out.line("call pb_check_fits(pb_w, pb_size(pbb), pbn)");
                out.line(W_FAILED);
                out.line("call pb_write_buf(pb_w, pbb)");
                out.line("call pb_write_zero_bits(pb_w, (pbn - pb_size(pbb)) * 8)");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("call pb_check_len(pb_w, pb_size(pbb), {})", self.scope.expr(e)));
                out.line(W_FAILED);
                out.line("call pb_write_buf(pb_w, pbb)");
            }
            _ => out.line("call pb_write_buf(pb_w, pbb)"),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = int64(codec.bits() as i64);
        match array {
            None => out.line(format!("call pb_write_zero_bits(pb_w, {})", bits)),
            Some(Count::Expr(e)) => out.line(format!(
                "call pb_write_zero_bits(pb_w, pb_mul(max({}, 0_int64), {}))",
                self.scope.expr(e),
                bits
            )),
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if ({}) then", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("end if");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("call pb_adopt_version(pb_w, int({}, int64), {}, {})", self.scope.field(m), min, latest));
        out.line(W_FAILED);
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &self.scope.field(m));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.scope.field(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("call pb_check_len(pb_w, pb_size({}), {})", place, self.scope.expr(e)));
            out.line(W_FAILED);
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("call pb_check_no_term(pb_w, {}, {})", place, byte_list(term)));
            out.line(W_FAILED);
            out.line(format!("call pb_write_buf(pb_w, {})", place));
            out.line(format!("call pb_write_bytes(pb_w, {})", byte_list(term)));
        } else if ty.is_byte() {
            out.line(format!("call pb_write_buf(pb_w, {})", place));
        } else {
            let i = self.locals.var("pbi", "integer(int64)");
            let mac = if matches!(codec, Codec::Mac) { "%b" } else { "" };
            out.open(format!("do {} = 1, pb_size({})", i, place));
            out.line("call pb_at_index(pb_w, pbi - 1)");
            write_elem(&self.scope, out, codec, ty, &format!("{}(pbi){}", place, mac));
            out.close("end do");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let c = self.locals.var("pbc", "integer(int64)");
        out.line(format!("{} = 0", c));
        for part in parts {
            let m = self.scope.member(part.member);
            let v = format!("int({}, int64)", self.scope.field(m));
            check_bits(out, &v, part.width, part.signed);
            out.line(format!("pbc = ior(pbc, ishft(iand({}, {}), {}))", v, int64(mask(part.width) as i64), part.shift));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("call pb_write_uint(pb_w, pbc, {}, {})", nbytes, Fortran::little(endian)))
            }
            _ => out.line(format!("call pb_write_bits(pb_w, pbc, {})", container_width)),
        }
    }
}
