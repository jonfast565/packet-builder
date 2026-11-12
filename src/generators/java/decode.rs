//! Java decoder statements.

use super::expr::store_value;
use super::naming::{Java, arm_class, class_name, new_array, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Java>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// `new byte[] {0x0d, (byte) 0xff}`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> =
        bytes.iter().map(|b| if *b < 0x80 { format!("0x{:02x}", b) } else { format!("(byte) 0x{:02x}", b) }).collect();
    format!("new byte[] {{{}}}", items.join(", "))
}

/// The condition under which the selector in `var` picks `arm` (None: always).
pub fn arm_test(arm: &Arm, arms: &[Arm], var: &str) -> Option<String> {
    let any = |vals: &[i64]| vals.iter().map(|v| format!("{} == {}L", var, v)).collect::<Vec<_>>().join(" || ");
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("!({})", any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}

/// `pbR.readUint(2, false)`: the raw bits of an integer container.
pub fn read_raw(codec: &Codec, bits: u32) -> String {
    match codec {
        Codec::Bytes { nbytes, endian } => format!("pbR.readUint({}, {})", nbytes, Java::little(endian)),
        _ => format!("pbR.readBits({})", bits),
    }
}

/// `width` bits of the container `pbC` from bit `shift`, as `ty`.
pub fn part_value(ty: &ValueType, shift: u32, width: u32, signed: bool) -> String {
    let bits = format!("((pbC >>> {}) & 0x{:x}L)", shift, mask(width));
    if signed {
        format!("(({})Pb.sext({}, {}))", scalar_type(ty), bits, width)
    } else {
        format!("(({}){})", scalar_type(ty), bits)
    }
}

pub fn read_elem(scope: &Scope<'_, Java>, codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pbR.readUint({}, {})", nbytes, Java::little(endian)),
        Codec::Bits { width } => format!("pbR.readBits({})", width),
        Codec::Float { width: 32, endian } => {
            return format!("Float.intBitsToFloat((int)pbR.readUint(4, {}))", Java::little(endian));
        }
        Codec::Float { endian, .. } => {
            return format!("Double.longBitsToDouble(pbR.readUint(8, {}))", Java::little(endian));
        }
        Codec::Mac => return "pbR.readBytes(6)".into(),
        Codec::Varint(k) => format!("pbR.readVarint({})", k.id()),
        Codec::Packet(r) => return format!("{}.decodeFrom(pbR{})", class_name(&r.name), call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("(({})Pb.sext({}, {}))", st, raw, width),
        // A varint may hold more bits than an unsigned member: they are cut.
        ValueType::Int { width, signed: false } if *width < 64 && matches!(codec, Codec::Varint(_)) => {
            format!("(({})Pb.trunc({}, {}, false))", st, raw, width)
        }
        _ => format!("(({}){})", st, raw),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Java>,
    /// Byte buffers are views of the input.
    zero_copy: bool,
    /// The generated file's class (packet types in union arms use it).
    outer: &'a str,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, zero_copy: bool, outer: &'a str) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), zero_copy, outer }
    }

    /// The reader method for a byte buffer: a copy, or a view of the input.
    fn read_bytes(&self) -> &'static str {
        if self.zero_copy { "readBuffer" } else { "readBytes" }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let class = format!("{}.{}", class_name(u), arm_class(u, arm, self.outer));
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => format!("new {}()", class),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("new {}(pbR.{}(pbR.count({}, 8)))", class, self.read_bytes(), self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("new {}(pbR.{}(pbR.remainingBits() / 8))", class, self.read_bytes())
            }
            (Some(ty), Some(codec), None) => format!("new {}({})", class, read_elem(&self.scope, codec, ty)),
            _ => format!("new {}()", class),
        }
    }

    /// Read elements into a growable array until `stop` (with `pbLast`
    /// holding the element just read) or the end of the data.
    fn read_list(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, stop: Option<&TExpr>) {
        let byte = m.ty.is_byte();
        let elem = self.elem_type(m);
        out.open("{");
        out.line(format!("{}[] pbA = {};", elem, new_array(&elem, "8")));
        out.line("int pbN = 0;");
        out.open("while (pbR.remainingBits() > 0) {");
        out.line("pbR.atIndex(pbN);");
        let v = read_elem(&self.scope, codec, ty);
        let store = if byte { "(byte) pbLast" } else { "pbLast" };
        out.line(format!("{} pbLast = {};", scalar_type(ty), v));
        out.line("if (pbN == pbA.length) pbA = java.util.Arrays.copyOf(pbA, pbN * 2);");
        out.line(format!("pbA[pbN++] = {};", store));
        if let Some(cond) = stop {
            out.line(format!("if ({}) break;", self.scope.expr(cond)));
        }
        out.close("}");
        out.line(format!("{} = {};", self.scope.field(m), self.wrap(m, "java.util.Arrays.copyOf(pbA, pbN)")));
        out.close("}");
    }

    /// The element type of array member `m` (`byte` in byte buffers).
    fn elem_type(&self, m: &Member) -> String {
        if m.ty.is_byte() { "byte".into() } else { scalar_type(&m.ty) }
    }

    /// The array `a` as the value of array member `m` (a view, for a
    /// zero-copy byte buffer).
    fn wrap(&self, m: &Member, a: &str) -> String {
        if m.ty.is_byte() && self.zero_copy { format!("java.nio.ByteBuffer.wrap({})", a) } else { a.to_string() }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if (!{}) throw pbR.error(PbErrorKind.CONSTRAINT, {});",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbR.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = self.scope.field(m);
        out.open("{");
        out.line(format!("long pbSel = {};", self.scope.expr(selector)));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "pbSel").unwrap_or_else(|| "(true)".into());
            out.line(format!(
                "{}if {} {} = {};",
                if first { "" } else { "else " },
                test,
                place,
                self.arm_value(u, arm)
            ));
            first = false;
        }
        let otherwise = match arms.iter().find(|a| a.default) {
            Some(arm) => format!("{} = {};", place, self.arm_value(u, arm)),
            None => format!(
                "throw pbR.error(PbErrorKind.INVALID, {} + pbSel);",
                string_literal(&format!("no arm of `{}` for ", m.name))
            ),
        };
        out.line(if first { otherwise } else { format!("else {}", otherwise) });
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("long pb_win{} = pbR.pushLimit({});", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pbR.popLimit(pb_win{}, {});", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("long {} = pbR.positionBits();", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pbR.positionBits();", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if ((long){} != {}) throw pbR.error(PbErrorKind.MISMATCH, {});",
            self.scope.field(m),
            self.scope.expr(value),
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("long[] pbJ = pbR.jump({}, {});", from, self.scope.expr(offset)));
        out.line(format!(
            "{} = {}.decodeFrom(pbR{});",
            self.scope.field(m),
            class_name(&target.name),
            call_args(&self.scope, target)
        ));
        out.line("pbR.jumpBack(pbJ);");
        out.close("}");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbR.skipBits(Pb.pad(pbR.positionBits() - pb_start, {}));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} = {};", self.scope.field(m), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pbR.readCString()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pbR.readUntil({}, {})", byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pbR.readBytes(pbR.count({}, 8))", read_elem(&self.scope, prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pbR.readBytes(pbR.count({}, 8))", self.scope.expr(e)),
            _ => "pbR.readBytes(pbR.remainingBits() / 8)".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("{} = pbR.utf8({}, {});", self.scope.field(m), raw, padded));
        } else {
            out.line(format!("{} = pbR.text({}, {}, {});", self.scope.field(m), raw, m.encoding.id(), padded));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbR.skipBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbR.skipBits((long)pbR.count({}, {}) * {});", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pbR.skipBits(pbR.remainingBits());"),
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
        out.line(format!("pbR.setVersion((long){}, {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        out.line(format!("{} = {};", self.scope.field(m), read_elem(&self.scope, codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = self.scope.field(m);
        let ebits = codec.min_elem_bits();
        match count {
            Count::Expr(e) => {
                let n = format!("pbR.count({}, {})", self.scope.expr(e), ebits);
                if m.ty.is_byte() && ty.is_byte() {
                    out.line(format!("{} = pbR.{}({});", target, self.read_bytes(), n));
                } else {
                    let elem = self.elem_type(m);
                    out.open("{");
                    out.line(format!("int pbN = {};", n));
                    out.line(format!("{}[] pbA = {};", elem, new_array(&elem, "pbN")));
                    out.open("for (int pbI = 0; pbI < pbN; pbI++) {");
                    out.line("pbR.atIndex(pbI);");
                    let v = read_elem(&self.scope, codec, ty);
                    out.line(format!("pbA[pbI] = {};", if m.ty.is_byte() { format!("(byte) {}", v) } else { v }));
                    out.close("}");
                    out.line(format!("{} = {};", target, self.wrap(m, "pbA")));
                    out.close("}");
                }
            }
            Count::Terminated { term, optional } => {
                let read = if self.zero_copy { "readUntilBuffer" } else { "readUntil" };
                out.line(format!("{} = pbR.{}({}, {});", target, read, byte_list(term), optional))
            }
            Count::Until(cond) => self.read_list(out, m, ty, codec, Some(cond)),
            Count::Remaining => {
                if m.ty.is_byte() && ty.is_byte() {
                    out.line(format!("{} = pbR.{}(pbR.remainingBits() / 8);", target, self.read_bytes()));
                } else {
                    self.read_list(out, m, ty, codec, None);
                }
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        out.line(format!("long pbC = {};", read_raw(container, container_width)));
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!("{} = {};", self.scope.field(m), part_value(&m.ty, part.shift, part.width, part.signed)));
        }
        out.close("}");
    }
}
