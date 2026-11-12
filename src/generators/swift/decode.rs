//! Swift decoder statements.

use super::expr::{negate, store_value};
use super::naming::{Swift, case_name, ident, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, ValueType};

/// Expression (to be preceded by `try`) that reads one element.
pub fn read_elem(scope: &Scope<'_, Swift>, codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let width = match ty {
        ValueType::Int { width, .. } => *width,
        _ => 0,
    };
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pbR.readUInt({}, {})", nbytes, Swift::little(endian)),
        Codec::Bits { width } => format!("pbR.readBits({})", width),
        Codec::Float { width: 32, endian } => {
            return format!(
                "Float(bitPattern: UInt32(truncatingIfNeeded: pbR.readUInt(4, {})))",
                Swift::little(endian)
            );
        }
        Codec::Float { endian, .. } => {
            return format!("Double(bitPattern: pbR.readUInt(8, {}))", Swift::little(endian));
        }
        Codec::Mac => return "pbR.readMac()".into(),
        Codec::Varint(k) => format!("pbR.readVarint({})", k.id()),
        Codec::Packet(r) => return format!("{}.decodeFrom(pbR{})", r.name, call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    if ty.is_signed() {
        format!("{}(truncatingIfNeeded: pbSext({}, {}))", st, raw, width)
    } else {
        format!("{}(truncatingIfNeeded: {})", st, raw)
    }
}

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Swift>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// `[0x0d, 0x0a]`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!("[{}]", items.join(", "))
}

pub struct Decoder<'a> {
    scope: Scope<'a, Swift>,
    /// Byte buffers are slices sharing the input's storage.
    zero_copy: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, zero_copy: bool) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), zero_copy }
    }

    /// The reader method for a byte buffer: a copy, or a slice.
    fn read_bytes(&self) -> &'static str {
        if self.zero_copy { "readSlice" } else { "readBytes" }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let v = case_name(arm);
        let read = match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => return format!("{}.{}", u, v),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("{}.{}(pbR.{}(pbR.count({}, 8)))", u, v, self.read_bytes(), self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("{}.{}(pbR.{}(pbR.remainingBits() / 8))", u, v, self.read_bytes())
            }
            (Some(ty), Some(codec), None) => format!("{}.{}({})", u, v, read_elem(&self.scope, codec, ty)),
            (Some(ty), ..) => return format!("{}.{}({})", u, v, super::naming::default_value(ty)),
        };
        format!("try {}", read)
    }

    fn fail(&self, kind: &str, message: &str) -> String {
        format!("throw pbR.error(.{}, {})", kind, string_literal(message))
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!("if {} {{ {} }}", negate(self.scope.expr(cond)), self.fail("constraint", message)));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbR.at({})", string_literal(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        out.open("do {");
        out.line(format!("let pb_sel: Int64 = {}", self.scope.expr(selector)));
        out.line("switch pb_sel {");
        let place = format!("p.{}", ident(&m.name));
        for arm in arms.iter().filter(|a| !a.default) {
            let pat: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            out.line(format!("case {}: {} = {}", pat.join(", "), place, self.arm_value(u, arm)));
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => out.line(format!("default: {} = {}", place, self.arm_value(u, arm))),
            None => out.line(format!("default: throw pbR.error(.invalid, \"no arm of `{}` for \\(pb_sel)\")", m.name)),
        }
        out.line("}");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("let pb_win{} = try pbR.pushLimit({})", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("try pbR.popLimit(pb_win{}, {})", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("let {} = pbR.positionBits()", mark_var(mark)));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("{} = pbR.positionBits()", mark_var(mark)));
    }

    fn declare_mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("var {} = pbR.positionBits()", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if pbI(p.{}) != {} {{ {} }}",
            ident(&m.name),
            self.scope.expr(value),
            self.fail("mismatch", &format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("do {");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("let pb_j = try pbR.jump({}, {})", from, self.scope.expr(offset)));
        out.line(format!(
            "p.{} = try {}.decodeFrom(pbR{})",
            ident(&m.name),
            target.name,
            call_args(&self.scope, target)
        ));
        out.line("pbR.jumpBack(pb_j)");
        out.close("}");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("try pbR.skipBits(pbPad(pbR.positionBits() - pb_start, {}))", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {}", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        out.open("do {");
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pbR.readCStringSlice()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pbR.readUntilSlice({}, {})", byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                let len = read_elem(&self.scope, prefix, &PREFIX_LEN);
                out.line(format!("let pb_n = try Int64(truncatingIfNeeded: {})", len));
                "pbR.readSlice(pbR.count(pb_n, 8))".to_string()
            }
            (_, Some(Count::Expr(e))) => format!("pbR.readSlice(pbR.count({}, 8))", self.scope.expr(e)),
            _ => "pbR.readSlice(pbR.remainingBits() / 8)".to_string(),
        };
        out.line(format!("let pb_t = try {}", raw));
        out.line(format!(
            "p.{} = try pbR.text(pb_t, {}, {})",
            ident(&m.name),
            m.encoding.id(),
            *mode == StrMode::Padded
        ));
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("try pbR.skipBits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("try pbR.skipBits(pbR.count({}, {}) * {})", self.scope.expr(e), bits, bits));
            }
            Some(Count::Remaining) => out.line("try pbR.skipBits(pbR.remainingBits())"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        let read = read_elem(&self.scope, codec, ty);
        // A re-declaration narrower than the member (`@3 count uint32`).
        let read = if &m.ty != ty { format!("{}(truncatingIfNeeded: {})", scalar_type(&m.ty), read) } else { read };
        out.line(format!("p.{} = try {}", ident(&m.name), read));
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if {} {{", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("}");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("try pbR.setVersion(pbI(p.{}), {}, {})", ident(&m.name), min, latest));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        let n = match count {
            Count::Expr(e) => format!("pbR.count({}, {})", self.scope.expr(e), ebits),
            Count::Terminated { term, optional } => {
                let read = if self.zero_copy { "readUntilSlice" } else { "readUntil" };
                out.line(format!("{} = try pbR.{}({}, {})", target, read, byte_list(term), optional));
                return;
            }
            Count::Until(cond) => {
                out.open("while pbR.remainingBits() > 0 {");
                out.line(format!("pbR.atIndex({}.count)", target));
                out.line(format!("let pb_last = try {}", read_elem(&self.scope, codec, ty)));
                out.line(format!("let pb_stop = {}", self.scope.expr(cond)));
                out.line(format!("{}.append(pb_last)", target));
                out.line("if pb_stop { break }");
                out.close("}");
                return;
            }
            Count::Remaining => String::new(),
        };
        if ty.is_byte() {
            let read = match count {
                Count::Expr(_) => format!("pbR.{}({})", self.read_bytes(), n),
                _ => format!("pbR.{}(pbR.remainingBits() / 8)", self.read_bytes()),
            };
            out.line(format!("{} = try {}", target, read));
            return;
        }
        match count {
            Count::Expr(_) => {
                out.open("do {");
                out.line(format!("let pb_n = try {}", n));
                out.open("for pb_i in 0..<pb_n {");
                out.line("pbR.atIndex(pb_i)");
                out.line(format!("{}.append(try {})", target, read_elem(&self.scope, codec, ty)));
                out.close("}");
                out.close("}");
            }
            _ => {
                out.open("while pbR.remainingBits() > 0 {");
                out.line(format!("pbR.atIndex({}.count)", target));
                out.line(format!("{}.append(try {})", target, read_elem(&self.scope, codec, ty)));
                out.close("}");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("do {");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pbR.readUInt({}, {})", nbytes, Swift::little(endian)),
            _ => format!("pbR.readBits({})", container_width),
        };
        out.line(format!("let pb_c: UInt64 = try {}", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!("p.{} = {}", ident(&m.name), bit_part(&m.ty, part.shift, part.width, part.signed)));
        }
        out.close("}");
    }
}

/// The member value held in bits `shift..shift+width` of `pb_c`.
pub fn bit_part(ty: &ValueType, shift: u32, width: u32, signed: bool) -> String {
    let bits = format!("((pb_c >> {}) & 0x{:x})", shift, mask(width));
    let st = scalar_type(ty);
    if signed {
        format!("{}(truncatingIfNeeded: pbSext({}, {}))", st, bits, width)
    } else {
        format!("{}(truncatingIfNeeded: {})", st, bits)
    }
}
