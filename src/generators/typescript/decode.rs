//! TypeScript decoder statements.

use super::expr::{store_value, to_i64};
use super::locals::Locals;
use super::naming::{TypeScript, byte_list, ident, is_big, type_name};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// How a value the reader returned is represented.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Repr {
    /// An integer `number` (up to 32 bits).
    Num,
    /// An integer `bigint`.
    Big,
    /// Anything else (floats, bytes, packets).
    Other,
}

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, TypeScript>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// A raw integer read from `codec` (`readUint`, `readBits`), as a number for
/// up to 32 bits and a bigint above.
pub fn read_raw(codec: &Codec, width: u32) -> (String, Repr) {
    match codec {
        Codec::Bytes { nbytes, endian } if *nbytes <= 4 => {
            (format!("pb_r.readUint({}, {})", nbytes, TypeScript::little(endian)), Repr::Num)
        }
        Codec::Bytes { nbytes, endian } => {
            (format!("pb_r.readUintBig({}, {})", nbytes, TypeScript::little(endian)), Repr::Big)
        }
        _ if width <= 32 => (format!("pb_r.readBits({})", width), Repr::Num),
        _ => (format!("pb_r.readBitsBig({})", width), Repr::Big),
    }
}

/// Sign-extend the low `width` bits of a raw value.
fn sext(raw: String, repr: Repr, width: u32) -> String {
    match repr {
        Repr::Num => format!("pbSext({}, {})", raw, width),
        _ => format!("BigInt.asIntN({}, {})", width, raw),
    }
}

/// A value read as `repr`, stored in a member of type `ty`.
pub fn into(v: String, repr: Repr, ty: &ValueType) -> String {
    match (repr, is_big(ty)) {
        (Repr::Num, true) => format!("BigInt({})", v),
        (Repr::Big, false) if matches!(ty, ValueType::Int { .. }) => format!("Number({})", v),
        _ => v,
    }
}

/// Bits `shift..shift + width` of the container in `var`, sign-extended
/// when `signed`.
pub fn extract(var: &str, repr: Repr, shift: u32, width: u32, signed: bool) -> (String, Repr) {
    let bits = match repr {
        Repr::Num if width == 32 => format!("({} >>> {})", var, shift),
        Repr::Num => format!("(({} >>> {}) & 0x{:x})", var, shift, mask(width)),
        _ => format!("(({} >> {}n) & 0x{:x}n)", var, shift, mask(width)),
    };
    if signed { (sext(bits, repr, width), repr) } else { (bits, repr) }
}

fn read_elem(scope: &Scope<'_, TypeScript>, codec: &Codec, ty: &ValueType) -> (String, Repr) {
    let (raw, repr) = match codec {
        Codec::Bytes { .. } | Codec::Bits { .. } => read_raw(codec, codec.bits()),
        Codec::Float { width, endian } => {
            let f = if *width == 32 { "readF32" } else { "readF64" };
            return (format!("pb_r.{}({})", f, TypeScript::little(endian)), Repr::Other);
        }
        Codec::Mac => return ("pb_r.readBytes(6)".into(), Repr::Other),
        Codec::Varint(k) => (format!("pb_r.readVarint({})", k.id()), Repr::Big),
        Codec::Packet(r) => {
            return (format!("{}.decodeFrom(pb_r{})", type_name(&r.name), call_args(scope, r)), Repr::Other);
        }
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => (sext(raw, repr, *width), repr),
        _ => (raw, repr),
    }
}

/// `read_elem`, stored in a member of type `target`.
fn read_into(scope: &Scope<'_, TypeScript>, codec: &Codec, ty: &ValueType, target: &ValueType) -> String {
    let (v, repr) = read_elem(scope, codec, ty);
    into(v, repr, target)
}

pub struct Decoder<'a> {
    scope: Scope<'a, TypeScript>,
    /// Byte buffers are views of the input.
    zero_copy: bool,
    pub locals: Locals,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, zero_copy: bool) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), zero_copy, locals: Locals::default() }
    }

    /// The reader method for a byte buffer: a copy, or a view.
    fn read_bytes(&self) -> &'static str {
        if self.zero_copy { "readView" } else { "readBytes" }
    }

    /// Expression that decodes the value of `arm`.
    fn arm_value(&self, arm: &Arm) -> String {
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => "null".into(),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("pb_r.{}(pb_r.count({}, 8))", self.read_bytes(), self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("pb_r.{}(Math.floor(pb_r.remainingBits() / 8))", self.read_bytes())
            }
            (Some(ty), Some(codec), None) => read_into(&self.scope, codec, ty, ty),
            _ => "null".into(),
        }
    }

    fn mark_local(&self, mark: Mark) -> String {
        let v = mark_var(mark);
        self.locals.declare(&v, "number", "0");
        v
    }
}

/// `(pb_sel === 1n || pb_sel === 2n)`, or `!(...)` of the other arms' values
/// for the default arm; None when every value picks `arm`.
pub fn arm_test(arm: &Arm, arms: &[Arm]) -> Option<String> {
    let any = |vals: &[i64]| vals.iter().map(|v| format!("pb_sel === {}n", v)).collect::<Vec<_>>().join(" || ");
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("!({})", any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if (!{}) throw pb_r.error(PbError.CONSTRAINT, {});",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_r.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let place = format!("p.{}", ident(&m.name));
        out.open("{");
        out.line(format!("const pb_sel = {};", self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms).unwrap_or_else(|| "true".into());
            out.open(format!("{}if ({}) {{", if first { "" } else { "} else " }, test));
            out.line(format!("{} = {{ kind: \"{}\", value: {} }};", place, arm.name, self.arm_value(arm)));
            out.pop();
            first = false;
        }
        if !first {
            out.open("} else {");
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => out.line(format!("{} = {{ kind: \"{}\", value: {} }};", place, arm.name, self.arm_value(arm))),
            None => out.line(format!("throw pb_r.error(PbError.INVALID, \"no arm of `{}` for \" + pb_sel);", m.name)),
        }
        if !first {
            out.close("}");
        }
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0n".into());
        self.locals.declare(&format!("pb_win{}", id), "number", "0");
        out.line(format!("pb_win{} = pb_r.pushLimit({});", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pb_r.popLimit(pb_win{}, {});", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pb_r.positionBits();", self.mark_local(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if ({} !== {}) throw pb_r.error(PbError.MISMATCH, {});",
            to_i64(self.scope.field(m), &m.ty),
            self.scope.expr(value),
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        out.open("{");
        out.line(format!("const pb_j = pb_r.jump({}, {});", from, self.scope.expr(offset)));
        out.line(format!(
            "p.{} = {}.decodeFrom(pb_r{});",
            ident(&m.name),
            type_name(&target.name),
            call_args(&self.scope, target)
        ));
        out.line("pb_r.jumpBack(pb_j);");
        out.close("}");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_r.skipBits(pbPad(pb_r.positionBits() - pb_start, {}));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {};", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pb_r.readCstring()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pb_r.readUntilView({}, {})", byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                let (n, repr) = read_elem(&self.scope, prefix, &PREFIX_LEN);
                format!("pb_r.readView(pb_r.count({}, 8))", into(n, repr, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pb_r.readView(pb_r.count({}, 8))", self.scope.expr(e)),
            _ => "pb_r.readView(Math.floor(pb_r.remainingBits() / 8))".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        if m.encoding == TextEncoding::Utf8 {
            let raw = if padded { format!("pbUntilNul({})", raw) } else { raw };
            out.line(format!("p.{} = pb_r.utf8({});", ident(&m.name), raw));
        } else {
            out.line(format!("p.{} = pb_r.text({}, {}, {});", ident(&m.name), raw, m.encoding.id(), padded));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_r.skipBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_r.skipBits(pb_r.count({}, {}) * {});", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pb_r.skipBits(pb_r.remainingBits());"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if ({}) {{", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("}");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("pb_r.setVersion({}, {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("p.{} = {};", ident(&m.name), read_into(&self.scope, codec, ty, &m.ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        let elem = || read_into(&self.scope, codec, ty, &m.ty);
        match count {
            Count::Expr(e) => {
                let n = format!("pb_r.count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} = pb_r.{}({});", target, self.read_bytes(), n));
                } else {
                    out.open("{");
                    out.line(format!("const pb_n = {};", n));
                    out.line(format!("{} = [];", target));
                    out.open("for (let pb_i = 0; pb_i < pb_n; pb_i++) {");
                    out.line("pb_r.atIndex(pb_i);");
                    out.line(format!("{}.push({});", target, elem()));
                    out.close("}");
                    out.close("}");
                }
            }
            Count::Terminated { term, optional } => {
                let read = if self.zero_copy { "readUntilView" } else { "readUntil" };
                out.line(format!("{} = pb_r.{}({}, {});", target, read, byte_list(term), optional))
            }
            Count::Until(cond) => {
                // Byte arrays are collected first, then made a Uint8Array.
                let list = if ty.is_byte() { "pb_a" } else { target.as_str() };
                out.open("{");
                if ty.is_byte() {
                    out.line("const pb_a: number[] = [];");
                } else {
                    out.line(format!("{} = [];", target));
                }
                out.open("while (pb_r.remainingBits() > 0) {");
                out.line(format!("pb_r.atIndex({}.length);", list));
                out.line(format!("const pb_last = {};", elem()));
                out.line(format!("{}.push(pb_last);", list));
                out.line(format!("if ({}) break;", self.scope.expr(cond)));
                out.close("}");
                if ty.is_byte() {
                    out.line(format!("{} = Uint8Array.from(pb_a);", target));
                }
                out.close("}");
            }
            Count::Remaining => {
                if ty.is_byte() {
                    out.line(format!("{} = pb_r.{}(Math.floor(pb_r.remainingBits() / 8));", target, self.read_bytes()));
                } else {
                    out.line(format!("{} = [];", target));
                    out.open("while (pb_r.remainingBits() > 0) {");
                    out.line(format!("pb_r.atIndex({}.length);", target));
                    out.line(format!("{}.push({});", target, elem()));
                    out.close("}");
                }
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let (raw, repr) = read_raw(container, container_width);
        out.open("{");
        out.line(format!("const pb_c = {};", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let (v, r) = extract("pb_c", repr, part.shift, part.width, part.signed);
            out.line(format!("p.{} = {};", ident(&m.name), into(v, r, &m.ty)));
        }
        out.close("}");
    }
}
