//! Ada encoder statements.

use super::decode::{arm_test, call_args};
use super::expr::store_value;
use super::locals::Locals;
use super::naming::{Ada, ada_string, arm_literal, byte_list, calc_var, ident, scalar_type};
use super::types::Boxes;
use crate::generators::common::union::{mismatch_message, uses_selector};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// `v` as stored, unboxed.
pub fn unboxed(v: String, boxed: bool) -> String {
    if boxed { format!("Element ({}, 0)", v) } else { v }
}

fn write_elem(scope: &Scope<'_, Ada>, out: &mut Out, codec: &Codec, ty: &ValueType, v: &str) {
    if let ValueType::Int { width, signed } = ty
        && ty.needs_range_check()
    {
        if *signed {
            out.line(format!("Pb_Check_I (W, Pb_I ({}), {});", v, width));
        } else {
            out.line(format!("Pb_Check_U (W, Pb_U ({}), {});", v, width));
        }
    }
    match codec {
        Codec::Bytes { nbytes, endian } => {
            out.line(format!("Pb_Write_Uint (W, Pb_U ({}), {}, {});", v, nbytes, Ada::little(endian)))
        }
        Codec::Bits { width } => out.line(format!("Pb_Write_Bits (W, Pb_U ({}), {});", v, width)),
        Codec::Float { width: 32, endian } => {
            out.line(format!("Pb_Write_Uint (W, Pb_F32_Bits ({}), 4, {});", v, Ada::little(endian)))
        }
        Codec::Float { endian, .. } => {
            out.line(format!("Pb_Write_Uint (W, Pb_F64_Bits ({}), 8, {});", v, Ada::little(endian)))
        }
        Codec::Mac => out.line(format!("Pb_Write_Mac (W, {});", v)),
        Codec::Varint(k) => out.line(format!("Pb_Write_Varint (W, {}, Pb_U ({}));", k.id(), v)),
        Codec::Packet(r) => out.line(format!("Encode_To ({}, W{});", v, call_args(scope, r))),
        Codec::Str(_) => unreachable!("strings are handled by Encoder::string"),
    }
}

pub struct Encoder<'a> {
    pub scope: Scope<'a, Ada>,
    pub locals: &'a Locals,
    boxes: &'a Boxes,
}

impl<'a> Encoder<'a> {
    pub fn new(packet: &'a Packet, locals: &'a Locals, boxes: &'a Boxes) -> Self {
        Encoder { scope: Scope::new(packet, Mode::Encode), locals, boxes }
    }

    /// Member `m`'s value (unboxed).
    fn value(&self, m: &Member) -> String {
        unboxed(self.scope.field(m), self.boxes.member(&self.scope.packet.name, &m.name))
    }
}

impl StepEmitter for Encoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!("if not ({}) then", self.scope.expr(cond)));
        out.line(format!("   Pb_Fail (W, Pb_Constraint, {});", ada_string(message)));
        out.line("end if;");
    }

    fn encoding(&self) -> bool {
        true
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("Pb_Field (W, {});", ada_string(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = self.value(m);
        if uses_selector(arms) {
            let sel = self.locals.var("Pb_Sel", "Integer_64");
            out.line(format!("{} := {};", sel, self.scope.expr(selector)));
        }
        out.open(format!("case {}.Kind is", place));
        for arm in arms {
            out.open(format!("when {} =>", arm_literal(u, arm)));
            let mut wrote = false;
            if let Some(test) = arm_test(arm, arms, "Pb_Sel") {
                out.line(format!("if not {} then", test));
                out.line(format!("   Pb_Fail (W, Pb_Mismatch, {});", ada_string(&mismatch_message(&m.name, arm))));
                out.line("end if;");
                wrote = true;
            }
            let value = format!("{}.{}", place, ident(&arm.name));
            match (&arm.ty, &arm.codec, &arm.count) {
                (Some(_), _, Some(count)) => {
                    if let Count::Expr(e) = count
                        && !self.packet().depends_on_wire(e)
                    {
                        out.line(format!("Pb_Check_Len (W, Integer_64 ({}.Length), {});", value, self.scope.expr(e)));
                    }
                    out.line(format!("Pb_Write_Bytes (W, {});", value));
                    wrote = true;
                }
                (Some(ty), Some(codec), None) => {
                    let v = unboxed(value, self.boxes.member(u, &arm.name));
                    write_elem(&self.scope, out, codec, ty, &v);
                    wrote = true;
                }
                _ => {}
            }
            if !wrote {
                out.line("null;");
            }
            out.pop();
        }
        out.line("when others =>");
        out.line(format!("   Pb_Fail (W, Pb_Invalid, {});", ada_string(&format!("`{}` holds no known arm", m.name))));
        out.close("end case;");
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        out.open("declare");
        out.line("Pb_S : aliased Pb_Writer;");
        out.close("begin");
        out.push();
        out.line(format!("Pb_Sub (W, {}, {}, {}, Pb_S'Access);", from, self.scope.expr(offset), Ada::flag(root)));
        out.line(format!("Encode_To ({}, Pb_S'Access{});", self.value(m), call_args(&self.scope, target)));
        out.line("Pb_Place (W, Pb_S'Access);");
        out.close("end;");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        if let Some(e) = size {
            let w = self.locals.var(format!("pb_win{}", id), "Integer_64");
            let z = self.locals.var(format!("pb_wsz{}", id), "Integer_64");
            out.line(format!("{} := Pb_Pos (W);", w));
            out.line(format!("{} := {};", z, self.scope.expr(e)));
        }
    }

    fn close_window(&self, out: &mut Out, id: usize, sized: bool, exact: bool) {
        if sized {
            out.line(format!("Pb_End_Window (W, pb_win{}, pb_wsz{}, {});", id, id, Ada::flag(exact)));
        }
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals.var(mark_var(mark), "Integer_64");
        out.line(format!("{} := Pb_Pos (W);", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn define_local(&self, out: &mut Out, m: &Member, value: &TExpr) {
        let name = calc_var(&m.name);
        if m.is_derived() {
            self.locals.var(&name, "Integer_64");
            out.line(format!("{} := {};", name, self.scope.expr(value)));
        } else {
            self.locals.var(&name, &scalar_type(&m.ty));
            out.line(format!("{} := {};", name, store_value(self.scope.expr(value), &m.ty)));
        }
    }

    fn write_derived(&self, out: &mut Out, m: &Member, codec: &Codec, at: Option<Mark>) {
        let v = calc_var(&m.name);
        let u = format!("Pb_I2U ({})", v);
        if let ValueType::Int { width, signed } = &m.ty {
            if *signed {
                out.line(format!("Pb_Check_I (W, {}, {});", v, width));
            } else {
                out.line(format!("Pb_Check_U (W, {}, {});", u, width));
            }
        }
        match (codec, at) {
            (Codec::Bytes { nbytes, endian }, None) => {
                out.line(format!("Pb_Write_Uint (W, {}, {}, {});", u, nbytes, Ada::little(endian)))
            }
            (Codec::Bytes { nbytes, endian }, Some(at)) => {
                out.line(format!("Pb_Patch_Uint (W, {}, {}, {}, {});", mark_var(at), u, nbytes, Ada::little(endian)))
            }
            (Codec::Bits { width }, None) => out.line(format!("Pb_Write_Bits (W, {}, {});", u, width)),
            (Codec::Bits { width }, Some(at)) => {
                out.line(format!("Pb_Patch_Bits (W, {}, {}, {});", mark_var(at), u, width))
            }
            // Varints are never patched (rejected by the analysis).
            (Codec::Varint(k), None) => out.line(format!("Pb_Write_Varint (W, {}, {});", k.id(), u)),
            _ => unreachable!("derived fields are integers"),
        }
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("Pb_Write_Zero_Bits (W, Pb_Pad (Pb_Pos (W) - pb_start, {}));", bytes * 8))
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        self.locals.var("Pb_B", "Pb_Bytes");
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("Pb_B := Pb_Utf8_Bytes (W, {});", self.scope.field(m)));
        } else {
            out.line(format!("Pb_B := Pb_Text_Bytes (W, {}, {});", self.scope.field(m), m.encoding.id()));
        }
        match (mode, array) {
            (StrMode::CString, _) => {
                out.line("Pb_Check_No_Nul (W, Pb_Arr (Pb_B));");
                out.line("Pb_Write_Bytes (W, Pb_B);");
                out.line("Pb_Write_Bytes (W, Pb_Byte_Array'(0 => 0));");
            }
            (StrMode::Terminated { term, .. }, _) => {
                out.line(format!("Pb_Check_No_Term (W, Pb_Arr (Pb_B), {});", byte_list(term)));
                out.line("Pb_Write_Bytes (W, Pb_B);");
                out.line(format!("Pb_Write_Bytes (W, {});", byte_list(term)));
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                out.line(format!("Pb_Check_U (W, Unsigned_64 (Pb_B.Length), {});", width));
                write_elem(&self.scope, out, prefix, &PREFIX_LEN, "Unsigned_64 (Pb_B.Length)");
                out.line("Pb_Write_Bytes (W, Pb_B);");
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                self.locals.var("Pb_Len", "Integer_64");
                out.line(format!("Pb_Len := {};", self.scope.expr(e)));
                out.line("Pb_Check_Fits (W, Integer_64 (Pb_B.Length), Pb_Len);");
                out.line("Pb_Write_Bytes (W, Pb_B);");
                out.line("Pb_Write_Zero_Bits (W, Pb_Mul (Pb_Minus (Pb_Len, Integer_64 (Pb_B.Length)), 8));");
            }
            (_, Some(Count::Expr(e))) if !self.packet().depends_on_wire(e) => {
                out.line(format!("Pb_Check_Len (W, Integer_64 (Pb_B.Length), {});", self.scope.expr(e)));
                out.line("Pb_Write_Bytes (W, Pb_B);");
            }
            _ => out.line("Pb_Write_Bytes (W, Pb_B);"),
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("Pb_Write_Zero_Bits (W, {});", bits)),
            Some(Count::Expr(e)) => out.line(format!(
                "Pb_Write_Zero_Bits (W, Pb_Mul (Integer_64'Max ({}, 0), {}));",
                self.scope.expr(e),
                bits
            )),
            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
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
        out.line(format!("Pb_Adopt_Version (W.T, Pb_I ({}), {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        write_elem(&self.scope, out, codec, ty, &self.value(m));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.scope.field(m);
        if let Count::Expr(e) = count
            && !self.packet().depends_on_wire(e)
        {
            out.line(format!("Pb_Check_Len (W, Integer_64 ({}.Length), {});", place, self.scope.expr(e)));
        }
        if let Count::Terminated { term, .. } = count {
            out.line(format!("Pb_Check_No_Term (W, Pb_Arr ({}), {});", place, byte_list(term)));
            out.line(format!("Pb_Write_Bytes (W, {});", place));
            out.line(format!("Pb_Write_Bytes (W, {});", byte_list(term)));
        } else if ty.is_byte() {
            out.line(format!("Pb_Write_Bytes (W, {});", place));
        } else {
            out.open(format!("for Pb_K in 0 .. Integer ({}.Length) - 1 loop", place));
            out.line("Pb_Index (W, Integer_64 (Pb_K));");
            write_elem(&self.scope, out, codec, ty, &format!("{}.Element (Pb_K)", place));
            out.close("end loop;");
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let c = self.locals.var("Pb_C", "Unsigned_64");
        out.line(format!("{} := 0;", c));
        for part in parts {
            let m = self.scope.member(part.member);
            let place = self.scope.field(m);
            if part.signed {
                out.line(format!("Pb_Check_I (W, Pb_I ({}), {});", place, part.width));
            } else {
                out.line(format!("Pb_Check_U (W, Pb_U ({}), {});", place, part.width));
            }
            out.line(format!(
                "Pb_C := Pb_C or Shift_Left (Pb_U ({}) and 16#{:X}#, {});",
                place,
                mask(part.width),
                part.shift
            ));
        }
        match container {
            Codec::Bytes { nbytes, endian } => {
                out.line(format!("Pb_Write_Uint (W, Pb_C, {}, {});", nbytes, Ada::little(endian)))
            }
            _ => out.line(format!("Pb_Write_Bits (W, Pb_C, {});", container_width)),
        }
    }
}
