//! Fortran decoder statements. Errors are recorded on the reader
//! (`pb_r%e`); every statement that may fail is followed by a return.

use super::expr::{int64, last_var, store_value};
use super::locals::Locals;
use super::naming::{
    Fortran, arm_component, byte_list, component, elem_type, f_string, int_kind, real_kind, type_name,
};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, Ty, ValueType};

/// The condition under which the selector in `var` picks `arm`, or None
/// when every value does (`common::union::arm_test` with int64 literals,
/// which values beyond the default integer kind need).
pub fn arm_test(arm: &Arm, arms: &[Arm], var: &str) -> Option<String> {
    let any =
        |vals: &[i64]| vals.iter().map(|v| format!("{} == {}", var, int64(*v))).collect::<Vec<_>>().join(" .or. ");
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("(.not. ({}))", any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}

/// Return when the reader holds an error.
pub const R_FAILED: &str = "if (pb_r%e%kind /= PB_OK) return";

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Fortran>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// Fail with `kind` and `message` (a Fortran string expression), then return.
pub fn fail(out: &mut Out, stream: &str, kind: &str, message: &str) {
    out.line(format!("call pb_fail({}, {}, {})", stream, kind, message));
    out.line("return");
}

/// `iand(shiftr(pbc, 3), 7_int64)` stored in `ty`, sign-extended for
/// signed parts.
pub fn bits_value(ty: &ValueType, var: &str, shift: u32, width: u32, signed: bool) -> String {
    let bits = format!("iand(shiftr({}, {}), {})", var, shift, int64(mask(width) as i64));
    let v = if signed && width < 64 { format!("pb_sext({}, {})", bits, width) } else { bits };
    convert_int(v, ty)
}

/// An int64 holding a value that fits `ty`, converted to its storage.
fn convert_int(v: String, ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => {
            let kind = int_kind(*width, *signed);
            if kind == "int64" { v } else { format!("int({}, {})", v, kind) }
        }
        _ => v,
    }
}

/// The raw int64 a codec reads (an integer codec).
pub fn read_raw(codec: &Codec) -> String {
    match codec {
        Codec::Bytes { nbytes, endian } => format!("pb_read_uint(pb_r, {}, {})", nbytes, Fortran::little(endian)),
        Codec::Varint(k) => format!("pb_read_varint(pb_r, {})", k.id()),
        Codec::Float { width, endian } => {
            format!("pb_read_uint(pb_r, {}, {})", width / 8, Fortran::little(endian))
        }
        _ => format!("pb_read_bits(pb_r, {})", codec.bits()),
    }
}

/// The value of `ty` read with `codec` (not a packet or a hardware address).
pub fn read_value(codec: &Codec, ty: &ValueType) -> String {
    let raw = read_raw(codec);
    match (ty, codec) {
        (ValueType::Float { width }, Codec::Float { width: 32, .. }) => {
            format!("real(pb_bits_f32({}), {})", raw, real_kind(*width))
        }
        (ValueType::Float { width }, _) => format!("real(pb_bits_f64({}), {})", raw, real_kind(*width)),
        (ValueType::Int { width, signed }, _) => {
            let v = if matches!(codec, Codec::Varint(_)) || codec.bits() > *width {
                if *width >= 64 { raw } else { format!("pb_trunc({}, {}, {})", raw, width, Fortran::flag(*signed)) }
            } else if *signed && *width < 64 {
                format!("pb_sext({}, {})", raw, width)
            } else {
                raw
            };
            convert_int(v, ty)
        }
        _ => raw,
    }
}

pub struct Decoder<'a> {
    pub scope: Scope<'a, Fortran>,
    pub locals: &'a Locals,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, locals: &'a Locals) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), locals }
    }

    /// Read one value into `target`; `alloc`: the target is an allocatable
    /// scalar (packets elsewhere and union arms), `byte`: an element of a
    /// byte array (an int8 bit pattern).
    fn read_into(&self, out: &mut Out, codec: &Codec, ty: &ValueType, target: &str, alloc: bool, byte: bool) {
        match codec {
            Codec::Packet(r) => {
                if alloc {
                    out.line(format!("allocate({})", target));
                }
                out.line(format!(
                    "call {}_decode_from({}, pb_r{})",
                    type_name(&r.name),
                    target,
                    call_args(&self.scope, r)
                ));
            }
            Codec::Mac => out.line(format!("call pb_read_mac(pb_r, {})", target)),
            Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
            _ if byte => out.line(format!("{} = pb_i8({})", target, read_raw(codec))),
            _ => out.line(format!("{} = {}", target, read_value(codec, ty))),
        }
        out.line(R_FAILED);
    }

    /// `pbn = <e>`, then checked against the data left for elements of
    /// `elem_bits` bits.
    fn count(&self, out: &mut Out, e: &TExpr, elem_bits: u64) {
        let n = self.locals.var("pbn", "integer(int64)");
        out.line(format!("{} = {}", n, self.scope.expr(e)));
        out.line(format!("pbn = pb_count(pb_r, pbn, {})", int64(elem_bits as i64)));
        out.line(R_FAILED);
    }

    /// Read the whole bytes left into byte buffer `target`.
    fn rest_bytes(&self, out: &mut Out, target: &str) {
        self.locals.var("pbn", "integer(int64)");
        out.line("pbn = pb_remaining_bits(pb_r) / 8");
        out.line(format!("call pb_read_bytes(pb_r, pbn, {})", target));
        out.line(R_FAILED);
    }

    fn arm_value(&self, out: &mut Out, place: &str, arm: &Arm) {
        let target = format!("{}%{}", place, arm_component(arm));
        match (&arm.ty, &arm.codec, &arm.count) {
            (Some(_), _, Some(Count::Expr(e))) => {
                self.count(out, e, 8);
                out.line(format!("call pb_read_bytes(pb_r, pbn, {})", target));
                out.line(R_FAILED);
            }
            (Some(_), _, Some(_)) => self.rest_bytes(out, &target),
            (Some(ty), Some(codec), None) => {
                let alloc = matches!(codec, Codec::Packet(_));
                self.read_into(out, codec, ty, &target, alloc, false)
            }
            _ => {}
        }
    }

    /// The local an `until` condition reads, set from element `elem`.
    fn set_last(&self, out: &mut Out, ty: &ValueType, elem: &str) {
        match ty {
            ValueType::Packet(n) | ValueType::Union(n) => {
                let v = self.locals.var(last_var(Some(n), Ty::Int), &format!("type({})", type_name(n)));
                out.line(format!("{} = {}", v, elem));
            }
            ValueType::Float { .. } => {
                let v = self.locals.var(last_var(None, Ty::Float), "real(real64)");
                out.line(format!("{} = real({}, real64)", v, elem));
            }
            _ if ty.is_byte() => {
                let v = self.locals.var(last_var(None, Ty::Int), "integer(int64)");
                out.line(format!("{} = pb_u8({})", v, elem));
            }
            _ => {
                let v = self.locals.var(last_var(None, Ty::Int), "integer(int64)");
                out.line(format!("{} = int({}, int64)", v, elem));
            }
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.open(format!("if (.not. {}) then", self.scope.expr(cond)));
        fail(out, "pb_r", "PB_CONSTRAINT", &f_string(message));
        out.close("end if");
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("call pb_at(pb_r, {})", f_string(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let place = self.scope.field(m);
        let sel = self.locals.var("pbsel", "integer(int64)");
        out.line(format!("{} = {}", sel, self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "pbsel").unwrap_or_else(|| ".true.".into());
            out.open(format!("{}if {} then", if first { "" } else { "else " }, test));
            out.line(format!("{}%pb_arm = {}", place, index_of(arms, arm)));
            self.arm_value(out, &place, arm);
            out.pop();
            first = false;
        }
        if !first {
            out.open("else");
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => {
                out.line(format!("{}%pb_arm = {}", place, index_of(arms, arm)));
                self.arm_value(out, &place, arm);
            }
            None => fail(
                out,
                "pb_r",
                "PB_INVALID",
                &format!("{} // pb_itoa(pbsel)", f_string(&format!("no arm of `{}` for ", m.name))),
            ),
        }
        if !first {
            out.close("end if");
        }
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0_int64".into());
        let n = self.locals.var("pbn", "integer(int64)");
        let v = self.locals.var(format!("pb_win{}", id), "integer(int64)");
        out.line(format!("{} = {}", n, size));
        out.line(format!("{} = pb_push_limit(pb_r, pbn)", v));
        out.line(R_FAILED);
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("call pb_pop_limit(pb_r, pb_win{}, {})", id, Fortran::flag(exact)));
        out.line(R_FAILED);
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals.var(mark_var(mark), "integer(int64)");
        out.line(format!("{} = pb_r%pos", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.open(format!("if (int({}, int64) /= {}) then", self.scope.field(m), self.scope.expr(value)));
        fail(
            out,
            "pb_r",
            "PB_MISMATCH",
            &f_string(&format!("`{}` does not match the value computed from the data", m.name)),
        );
        out.close("end if");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0_int64" } else { "pb_start" };
        let n = self.locals.var("pbn", "integer(int64)");
        let j = self.locals.var("pbj", "type(pb_jump_state)");
        let place = self.scope.field(m);
        out.line(format!("{} = {}", n, self.scope.expr(offset)));
        out.line(format!("call pb_jump(pb_r, {}, pbn, {})", from, j));
        out.line(R_FAILED);
        out.line(format!("allocate({})", place));
        out.line(format!(
            "call {}_decode_from({}, pb_r{})",
            type_name(&target.name),
            place,
            call_args(&self.scope, target)
        ));
        out.line(R_FAILED);
        out.line("call pb_jump_back(pb_r, pbj)");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        self.locals.var("pbn", "integer(int64)");
        out.line(format!("pbn = pb_pad(pb_r%pos - pb_start, {})", int64(bytes as i64 * 8)));
        out.line("call pb_skip_bits(pb_r, pbn)");
        out.line(R_FAILED);
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} = {}", self.scope.field(m), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let b = self.locals.array("pbb", "integer(int8)");
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line(format!("call pb_read_cstring(pb_r, {})", b));
                out.line(R_FAILED);
            }
            (StrMode::Terminated { term, optional }, _) => {
                out.line(format!("call pb_read_until(pb_r, {}, {}, {})", byte_list(term), Fortran::flag(*optional), b));
                out.line(R_FAILED);
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                self.locals.var("pbn", "integer(int64)");
                out.line(format!("pbn = {}", read_value(prefix, &PREFIX_LEN)));
                out.line(R_FAILED);
                out.line("pbn = pb_count(pb_r, pbn, 8_int64)");
                out.line(R_FAILED);
                out.line(format!("call pb_read_bytes(pb_r, pbn, {})", b));
                out.line(R_FAILED);
            }
            (_, Some(Count::Expr(e))) => {
                self.count(out, e, 8);
                out.line(format!("call pb_read_bytes(pb_r, pbn, {})", b));
                out.line(R_FAILED);
            }
            _ => self.rest_bytes(out, &b),
        }
        out.line(format!(
            "call pb_decode_text(pb_r, pbb, {}, {}, {})",
            m.encoding.id(),
            Fortran::flag(*mode == StrMode::Padded),
            self.scope.field(m)
        ));
        out.line(R_FAILED);
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits() as i64;
        match array {
            None => {
                out.line(format!("call pb_skip_bits(pb_r, {})", int64(bits)));
                out.line(R_FAILED);
            }
            Some(Count::Expr(e)) => {
                self.count(out, e, bits as u64);
                out.line(format!("call pb_skip_bits(pb_r, pbn * {})", int64(bits)));
                out.line(R_FAILED);
            }
            Some(Count::Remaining) => {
                self.locals.var("pbn", "integer(int64)");
                out.line("pbn = pb_remaining_bits(pb_r)");
                out.line("call pb_skip_bits(pb_r, pbn)");
            }
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
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
        out.line(format!("call pb_set_version(pb_r, int({}, int64), {}, {})", self.scope.field(m), min, latest));
        out.line(R_FAILED);
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        self.read_into(out, codec, ty, &self.scope.field(m), false, false);
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = self.scope.field(m);
        let byte = ty.is_byte();
        let mac = if matches!(codec, Codec::Mac) { "%b" } else { "" };
        match count {
            Count::Expr(e) => {
                self.count(out, e, codec.min_elem_bits());
                if byte {
                    out.line(format!("call pb_read_bytes(pb_r, pbn, {})", target));
                    out.line(R_FAILED);
                } else {
                    let i = self.locals.var("pbi", "integer(int64)");
                    out.line(format!("allocate({}(pbn))", target));
                    out.open(format!("do {} = 1, pbn", i));
                    out.line("call pb_at_index(pb_r, pbi - 1)");
                    self.read_into(out, codec, ty, &format!("{}(pbi){}", target, mac), false, false);
                    out.close("end do");
                }
            }
            Count::Terminated { term, optional } => {
                out.line(format!(
                    "call pb_read_until(pb_r, {}, {}, {})",
                    byte_list(term),
                    Fortran::flag(*optional),
                    target
                ));
                out.line(R_FAILED);
            }
            Count::Remaining if byte => self.rest_bytes(out, &target),
            Count::Until(_) | Count::Remaining => {
                let n = self.locals.var("pbn", "integer(int64)");
                let tmp = self.locals.array(format!("pbt_{}", component(&m.name)), &elem_type(ty));
                out.line(format!("{} = 0", n));
                out.line(format!("allocate({}(4))", target));
                out.open("do while (pb_remaining_bits(pb_r) > 0)");
                out.line("call pb_at_index(pb_r, pbn)");
                out.open(format!("if (pbn == size({}, kind=int64)) then", target));
                out.line(format!("allocate({}(2 * pbn + 4))", tmp));
                out.line(format!("{}(1:pbn) = {}(1:pbn)", tmp, target));
                out.line(format!("call move_alloc({}, {})", tmp, target));
                out.close("end if");
                out.line("pbn = pbn + 1");
                self.read_into(out, codec, ty, &format!("{}(pbn){}", target, mac), false, byte);
                if let Count::Until(cond) = count {
                    self.set_last(out, ty, &format!("{}(pbn)", target));
                    out.line(format!("if ({}) exit", self.scope.expr(cond)));
                }
                out.close("end do");
                out.line(format!("allocate({}(pbn))", tmp));
                out.line(format!("{} = {}(1:pbn)", tmp, target));
                out.line(format!("call move_alloc({}, {})", tmp, target));
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let raw = match container {
            Codec::Bytes { .. } => read_raw(container),
            _ => format!("pb_read_bits(pb_r, {})", container_width),
        };
        let c = self.locals.var("pbc", "integer(int64)");
        out.line(format!("{} = {}", c, raw));
        out.line(R_FAILED);
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!(
                "{} = {}",
                self.scope.field(m),
                bits_value(&m.ty, "pbc", part.shift, part.width, part.signed)
            ));
        }
    }
}

/// The tag of `arm`: its position among `arms`, from 1.
pub fn index_of(arms: &[Arm], arm: &Arm) -> usize {
    arms.iter().position(|a| std::ptr::eq(a, arm)).map(|i| i + 1).unwrap_or(1)
}
