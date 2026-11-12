//! Ada decoder statements.

use super::expr::{last_var, store_value};
use super::locals::Locals;
use super::naming::{Ada, ada_string, arm_literal, byte_list, ident, type_name};
use super::types::Boxes;
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{
    Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, Ty, ValueType,
    storage_for,
};

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Ada>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// The condition under which the selector in `var` picks `arm`, or None
/// when every value does.
pub fn arm_test(arm: &Arm, arms: &[Arm], var: &str) -> Option<String> {
    let any = |vals: &[i64]| vals.iter().map(|v| format!("{} = {}", var, v)).collect::<Vec<_>>().join(" or else ");
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("not ({})", any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}

/// An unsigned 64-bit value cut to `ty`'s storage, sign-extended from
/// `width` bits for signed types.
pub fn narrow(ty: &ValueType, raw: String, width: u32) -> String {
    match ty {
        ValueType::Int { width: w, signed: true } => match storage_for(*w) {
            64 => format!("Pb_Sext ({}, {})", raw, width),
            s => format!("Pb_To_I{} (Pb_Sext ({}, {}))", s, raw, width),
        },
        ValueType::Int { width: w, signed: false } => match storage_for(*w) {
            64 => raw,
            s => format!("Pb_To_U{} ({})", s, raw),
        },
        _ => raw,
    }
}

/// Part of the container in `var`: `width` bits from bit `shift`.
pub fn bits_value(ty: &ValueType, var: &str, shift: u32, width: u32, signed: bool) -> String {
    let bits = format!("(Shift_Right ({}, {}) and 16#{:X}#)", var, shift, mask(width));
    if signed {
        match storage_for(ty_width(ty)) {
            64 => format!("Pb_Sext ({}, {})", bits, width),
            s => format!("Pb_To_I{} (Pb_Sext ({}, {}))", s, bits, width),
        }
    } else {
        narrow(ty, bits, width)
    }
}

fn ty_width(ty: &ValueType) -> u32 {
    match ty {
        ValueType::Int { width, .. } => *width,
        _ => 64,
    }
}

/// The raw Unsigned_64 an integer codec reads.
fn read_raw(codec: &Codec) -> Option<String> {
    match codec {
        Codec::Bytes { nbytes, endian } => Some(format!("Pb_Read_Uint (R, {}, {})", nbytes, Ada::little(endian))),
        Codec::Bits { width } => Some(format!("Pb_Read_Bits (R, {})", width)),
        Codec::Varint(k) => Some(format!("Pb_Read_Varint (R, {})", k.id())),
        _ => None,
    }
}

pub fn read_elem(scope: &Scope<'_, Ada>, codec: &Codec, ty: &ValueType) -> String {
    match codec {
        Codec::Float { width: 32, endian } => {
            format!("Pb_Bits_To_F32 (Pb_Read_Uint (R, 4, {}))", Ada::little(endian))
        }
        Codec::Float { endian, .. } => format!("Pb_Bits_To_F64 (Pb_Read_Uint (R, 8, {}))", Ada::little(endian)),
        Codec::Mac => "Pb_Read_Mac (R)".into(),
        Codec::Packet(r) => format!("{}'(Decode_From (R{}))", type_name(&r.name), call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
        _ => {
            let raw = read_raw(codec).unwrap_or_default();
            narrow(ty, raw, ty_width(ty))
        }
    }
}

/// `v`, in a one-element array when it is stored boxed.
pub fn boxed(v: String, boxed: bool) -> String {
    if boxed { format!("Pb_Box ({})", v) } else { v }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Ada>,
    pub locals: &'a Locals,
    boxes: &'a Boxes,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, locals: &'a Locals, boxes: &'a Boxes) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), locals, boxes }
    }

    /// `v` as member `m` stores it.
    fn store(&self, m: &Member, v: String) -> String {
        boxed(v, self.boxes.member(&self.scope.packet.name, &m.name))
    }

    /// The aggregate that holds `arm` of union `u`, decoded.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let lit = arm_literal(u, arm);
        let value = match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => None,
            (Some(_), _, Some(Count::Expr(e))) => {
                Some(format!("Pb_Vec (Pb_Read_Bytes (R, Pb_Count (R, {}, 8)))", self.scope.expr(e)))
            }
            (Some(_), _, Some(_)) => Some("Pb_Vec (Pb_Read_Bytes (R, Pb_Remaining_Bits (R) / 8))".into()),
            (Some(ty), Some(codec), None) => {
                Some(boxed(read_elem(&self.scope, codec, ty), self.boxes.member(u, &arm.name)))
            }
            _ => None,
        };
        match value {
            Some(v) => format!("{}'(Kind => {}, {} => {})", type_name(u), lit, ident(&arm.name), v),
            None => format!("{}'(Kind => {})", type_name(u), lit),
        }
    }

    /// The local an `until` condition reads, set from the element just read.
    fn set_last(&self, out: &mut Out, ty: &ValueType, target: &str) {
        match ty {
            ValueType::Float { .. } => {
                let v = self.locals.var(last_var(None, Ty::Float), "IEEE_Float_64");
                out.line(format!("{} := Pb_F ({}.Last_Element);", v, target));
            }
            ValueType::Int { .. } => {
                let v = self.locals.var(last_var(None, Ty::Int), "Integer_64");
                out.line(format!("{} := Pb_I ({}.Last_Element);", v, target));
            }
            _ => {}
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!("if not ({}) then", self.scope.expr(cond)));
        out.line(format!("   Pb_Fail (R, Pb_Constraint, {});", ada_string(message)));
        out.line("end if;");
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("Pb_Field (R, {});", ada_string(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = self.scope.field(m);
        let sel = self.locals.var("Pb_Sel", "Integer_64");
        out.line(format!("{} := {};", sel, self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "Pb_Sel").unwrap_or_else(|| "True".into());
            out.line(format!("{} {} then", if first { "if" } else { "elsif" }, test));
            out.line(format!("   {} := {};", place, self.store(m, self.arm_value(u, arm))));
            first = false;
        }
        let otherwise = match arms.iter().find(|a| a.default) {
            Some(arm) => format!("{} := {};", place, self.store(m, self.arm_value(u, arm))),
            None => format!(
                "Pb_Fail (R, Pb_Invalid, {} & Pb_Img (Pb_Sel));",
                ada_string(&format!("no arm of `{}` for ", m.name))
            ),
        };
        if first {
            out.line(otherwise);
        } else {
            out.line("else");
            out.line(format!("   {}", otherwise));
            out.line("end if;");
        }
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        let v = self.locals.var(format!("pb_win{}", id), "Integer_64");
        out.line(format!("{} := Pb_Push_Limit (R, {});", v, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("Pb_Pop_Limit (R, pb_win{}, {});", id, Ada::flag(exact)));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals.var(mark_var(mark), "Integer_64");
        out.line(format!("{} := Pb_Pos (R);", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!("if Pb_I ({}) /= {} then", self.scope.field(m), self.scope.expr(value)));
        out.line(format!(
            "   Pb_Fail (R, Pb_Mismatch, {});",
            ada_string(&format!("`{}` does not match the value computed from the data", m.name))
        ));
        out.line("end if;");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        let j = self.locals.var("Pb_J", "Pb_Jump_State");
        out.line(format!("{} := Pb_Jump (R, {}, {});", j, from, self.scope.expr(offset)));
        let v = format!("{}'(Decode_From (R{}))", type_name(&target.name), call_args(&self.scope, target));
        out.line(format!("{} := {};", self.scope.field(m), self.store(m, v)));
        out.line("Pb_Jump_Back (R, Pb_J);");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("Pb_Skip_Bits (R, Pb_Pad (Pb_Pos (R) - pb_start, {}));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} := {};", self.scope.field(m), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "Pb_Read_CString (R)".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("Pb_Read_Until (R, {}, {})", byte_list(term), Ada::flag(*optional))
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("Pb_Read_Bytes (R, Pb_Count (R, Pb_U2I ({}), 8))", read_elem(&self.scope, prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("Pb_Read_Bytes (R, Pb_Count (R, {}, 8))", self.scope.expr(e)),
            _ => "Pb_Read_Bytes (R, Pb_Remaining_Bits (R) / 8)".to_string(),
        };
        let padded = Ada::flag(*mode == StrMode::Padded);
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("{} := Pb_Decode_Utf8 (R, {}, {});", self.scope.field(m), raw, padded));
        } else {
            out.line(format!(
                "{} := Pb_Decode_Text (R, {}, {}, {});",
                self.scope.field(m),
                raw,
                m.encoding.id(),
                padded
            ));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("Pb_Skip_Bits (R, {});", bits)),
            Some(Count::Expr(e)) => out.line(format!(
                "Pb_Skip_Bits (R, Pb_Mul (Pb_Count (R, {}, {}), {}));",
                self.scope.expr(e),
                bits,
                bits
            )),
            Some(Count::Remaining) => out.line("Pb_Skip_Bits (R, Pb_Remaining_Bits (R));"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if {} then", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("end if;");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("Pb_Set_Version (R.T, Pb_I ({}), {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("{} := {};", self.scope.field(m), self.store(m, read_elem(&self.scope, codec, ty))));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = self.scope.field(m);
        let ebits = codec.min_elem_bits();
        let elem = read_elem(&self.scope, codec, ty);
        let until_packet = match (count, ty) {
            (Count::Until(_), ValueType::Packet(n) | ValueType::Union(n)) => Some(n),
            _ => None,
        };
        match count {
            Count::Expr(e) => {
                let n = format!("Pb_Count (R, {}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} := Pb_Vec (Pb_Read_Bytes (R, {}));", target, n));
                } else {
                    self.locals.var("Pb_N", "Integer_64");
                    out.line(format!("Pb_N := {};", n));
                    out.line(format!("{}.Clear;", target));
                    out.open("for Pb_K in 0 .. Pb_N - 1 loop");
                    out.line("Pb_Index (R, Pb_K);");
                    out.line(format!("{}.Append ({});", target, elem));
                    out.close("end loop;");
                }
            }
            Count::Terminated { term, optional } => out.line(format!(
                "{} := Pb_Vec (Pb_Read_Until (R, {}, {}));",
                target,
                byte_list(term),
                Ada::flag(*optional)
            )),
            Count::Remaining if ty.is_byte() => {
                out.line(format!("{} := Pb_Vec (Pb_Read_Bytes (R, Pb_Remaining_Bits (R) / 8));", target));
            }
            Count::Until(_) | Count::Remaining => {
                self.locals.var("Pb_N", "Integer_64");
                out.line("Pb_N := 0;");
                out.line(format!("{}.Clear;", target));
                out.open("while Pb_Remaining_Bits (R) > 0 loop");
                out.line("Pb_Index (R, Pb_N);");
                match until_packet {
                    Some(n) => {
                        let v = self.locals.var(last_var(Some(n), Ty::Int), &type_name(n));
                        out.line(format!("{} := {};", v, elem));
                        out.line(format!("{}.Append ({});", target, v));
                    }
                    None => out.line(format!("{}.Append ({});", target, elem)),
                }
                out.line("Pb_N := Pb_N + 1;");
                if let Count::Until(cond) = count {
                    if until_packet.is_none() {
                        self.set_last(out, ty, &target);
                    }
                    out.line(format!("exit when {};", self.scope.expr(cond)));
                }
                out.close("end loop;");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("Pb_Read_Uint (R, {}, {})", nbytes, Ada::little(endian)),
            _ => format!("Pb_Read_Bits (R, {})", container_width),
        };
        let c = self.locals.var("Pb_C", "Unsigned_64");
        out.line(format!("{} := {};", c, raw));
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!(
                "{} := {};",
                self.scope.field(m),
                bits_value(&m.ty, "Pb_C", part.shift, part.width, part.signed)
            ));
        }
    }
}
