//! Lua decoder statements (the reader is `r`, the value `p`).

use super::expr::call_args;
use super::naming::{Lua, class};
use crate::generators::common::lua::{byte_string, store_value};
use crate::generators::common::union::{PY_LOGIC, arm_test};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// Expression reading one element.
pub fn read_elem(scope: &Scope<'_, Lua>, codec: &Codec, ty: &ValueType) -> String {
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("r:read_uint({}, {})", nbytes, Lua::little(endian)),
        Codec::Bits { width } => format!("r:read_bits({})", width),
        Codec::Float { width, endian } => return format!("r:read_float({}, {})", width, Lua::little(endian)),
        Codec::Mac => return "r:read_bytes(6)".into(),
        Codec::Varint(k) => format!("r:read_varint({})", k.id()),
        Codec::Packet(r) => return format!("{}.decode_from(r{})", class(&r.name), call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("pb_sext({}, {})", raw, width),
        _ => raw,
    }
}

/// Expression reading a container of `bits` bits (a bitfield).
pub fn read_container(container: &Codec, bits: u32) -> String {
    match container {
        Codec::Bytes { nbytes, endian } => format!("r:read_uint({}, {})", nbytes, Lua::little(endian)),
        _ => format!("r:read_bits({})", bits),
    }
}

/// `((pb_c >> shift) & mask)`, sign-extended when `signed`.
pub fn extract(shift: u32, width: u32, signed: bool) -> String {
    let bits = format!("((pb_c >> {}) & 0x{:x})", shift, mask(width));
    if signed { format!("pb_sext({}, {})", bits, width) } else { bits }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Lua>,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode) }
    }

    fn place(&self, m: &Member) -> String {
        self.scope.field(m)
    }

    /// Expression that decodes the value of `arm`.
    fn arm_value(&self, arm: &Arm) -> String {
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => "nil".into(),
            (Some(_), _, Some(Count::Expr(e))) => format!("r:read_bytes(r:count({}, 8))", self.scope.expr(e)),
            (Some(_), _, Some(Count::Remaining)) => "r:read_bytes(r:remaining() // 8)".into(),
            (Some(ty), Some(codec), None) => read_elem(&self.scope, codec, ty),
            _ => "nil".into(),
        }
    }

    /// `p.x = Union.new("arm", value)`.
    fn arm(&self, out: &mut Out, m: &Member, u: &str, arm: &Arm) {
        out.line(format!(
            "{} = {}.new({}, {})",
            self.place(m),
            class(u),
            string_literal(&arm.name),
            self.arm_value(arm)
        ));
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if not {} then r:fail(\"constraint\", {}) end",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("r:at({})", string_literal(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        out.line(format!("pb_sel = {}", self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "pb_sel", &PY_LOGIC).unwrap_or_else(|| "true".into());
            if first {
                out.open(format!("if {} then", test));
            } else {
                out.pop();
                out.open(format!("elseif {} then", test));
            }
            self.arm(out, m, u, arm);
            first = false;
        }
        if !first {
            out.pop();
            out.open("else");
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => self.arm(out, m, u, arm),
            None => out.line(format!(
                "r:fail(\"invalid\", {} .. pb_sel)",
                string_literal(&format!("no arm of `{}` for ", m.name))
            )),
        }
        if !first {
            out.close("end");
        }
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("local pb_win{} = r:push_limit({})", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("r:pop_limit(pb_win{}, {})", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("local {} = r.pos", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = r.pos", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if {} ~= {} then r:fail(\"mismatch\", {}) end",
            self.place(m),
            self.scope.expr(value),
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("pb_j = r:jump({}, {})", from, self.scope.expr(offset)));
        out.line(format!(
            "{} = {}.decode_from(r{})",
            self.place(m),
            class(&target.name),
            call_args(&self.scope, target)
        ));
        out.line("r:jump_back(pb_j)");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("r:skip_bits(pb_pad(r.pos - pb_start, {}))", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} = {}", self.place(m), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "r:read_cstring()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("r:read_until({}, {})", byte_string(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("r:read_bytes(r:count({}, 8))", read_elem(&self.scope, prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("r:read_bytes(r:count({}, 8))", self.scope.expr(e)),
            _ => "r:read_bytes(r:remaining() // 8)".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        let enc = if m.encoding == TextEncoding::Utf8 { 0 } else { m.encoding.id() };
        out.line(format!("{} = r:text({}, {}, {})", self.place(m), raw, enc, padded));
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("r:skip_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("r:skip_bits(r:count({}, {}) * {})", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("r:skip_bits(r:remaining())"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
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
        out.line(format!("r:set_version({}, {}, {})", self.place(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("{} = {}", self.place(m), read_elem(&self.scope, codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.place(m);
        let ebits = codec.min_elem_bits();
        let element = |out: &mut Out, index: &str| {
            out.line(format!("r:at_index({})", index));
            out.line(format!("pb_last = {}", read_elem(&self.scope, codec, ty)));
            out.line(format!("{}[#{} + 1] = pb_last", place, place));
        };
        match count {
            Count::Expr(e) if ty.is_byte() => {
                out.line(format!("{} = r:read_bytes(r:count({}, {}))", place, self.scope.expr(e), ebits))
            }
            Count::Remaining if ty.is_byte() => out.line(format!("{} = r:read_bytes(r:remaining() // 8)", place)),
            Count::Terminated { term, optional } => {
                out.line(format!("{} = r:read_until({}, {})", place, byte_string(term), optional))
            }
            Count::Expr(e) => {
                out.line(format!("{} = {{}}", place));
                out.line(format!("pb_n = r:count({}, {})", self.scope.expr(e), ebits));
                out.open("for pb_i = 0, pb_n - 1 do");
                element(out, "pb_i");
                out.close("end");
            }
            Count::Until(cond) => {
                out.line(format!("{} = {{}}", place));
                out.open("while r:remaining() > 0 do");
                element(out, &format!("#{}", place));
                out.line(format!("if {} then break end", self.scope.expr(cond)));
                out.close("end");
                if ty.is_byte() {
                    // Byte arrays are strings, as everywhere else.
                    out.line(format!("{} = pb_chars({})", place, place));
                }
            }
            Count::Remaining => {
                out.line(format!("{} = {{}}", place));
                out.open("while r:remaining() > 0 do");
                element(out, &format!("#{}", place));
                out.close("end");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.line(format!("pb_c = {}", read_container(container, container_width)));
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!("{} = {}", self.place(m), extract(part.shift, part.width, part.signed)));
        }
    }
}
