//! Object Pascal decoder statements.

use super::expr::{last_var, store_value};
use super::locals::Locals;
use super::naming::{Pascal, arm_class, byte_list, pas_string, scalar_type, type_name};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask};
use crate::ir::{
    Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, Ty, ValueType,
};

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Pascal>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// The condition under which the selector in `var` picks `arm`, or None
/// when every value does.
pub fn arm_test(arm: &Arm, arms: &[Arm], var: &str) -> Option<String> {
    let any = |vals: &[i64]| vals.iter().map(|v| format!("({} = {})", var, v)).collect::<Vec<_>>().join(" or ");
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("not ({})", any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}

/// `UInt16((pbC shr 3) and UInt64($7))`, sign-extended for signed parts.
pub fn bits_value(ty: &ValueType, var: &str, shift: u32, width: u32, signed: bool) -> String {
    let bits = format!("(({} shr {}) and UInt64(${:X}))", var, shift, mask(width));
    if signed {
        format!("{}(PbSext({}, {}))", scalar_type(ty), bits, width)
    } else {
        format!("{}({})", scalar_type(ty), bits)
    }
}

pub fn read_elem(scope: &Scope<'_, Pascal>, codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, Pascal::little(endian)),
        Codec::Bits { width } => format!("pbR.ReadBits({})", width),
        Codec::Float { width: 32, endian } => {
            return format!("PbBitsToSingle(pbR.ReadUint(4, {}))", Pascal::little(endian));
        }
        Codec::Float { endian, .. } => return format!("PbBitsToDouble(pbR.ReadUint(8, {}))", Pascal::little(endian)),
        Codec::Mac => return "pbR.ReadBytes(6)".into(),
        Codec::Varint(k) => format!("pbR.ReadVarint({})", k.id()),
        Codec::Packet(r) => return format!("{}.DecodeFrom(pbR{})", type_name(&r.name), call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("{}(PbSext({}, {}))", st, raw, width),
        _ => format!("{}({})", st, raw),
    }
}

pub struct Decoder<'a> {
    scope: Scope<'a, Pascal>,
    pub locals: &'a Locals,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, locals: &'a Locals) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), locals }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let class = arm_class(u, arm);
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => format!("{}.Create", class),
            (Some(_), _, Some(Count::Expr(e))) => {
                format!("{}.Create(pbR.ReadBytes(pbR.Count({}, 8)))", class, self.scope.expr(e))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                format!("{}.Create(pbR.ReadBytes(pbR.RemainingBits div 8))", class)
            }
            (Some(ty), Some(codec), None) => format!("{}.Create({})", class, read_elem(&self.scope, codec, ty)),
            _ => format!("{}.Create", class),
        }
    }

    /// Before a loop that grows array `target`: after it, its length is `pbN`.
    fn grow(&self, out: &mut Out, target: &str) {
        out.line(format!("if pbN = Length({}) then SetLength({}, 2 * pbN + 4);", target, target));
    }

    /// The local an `until` condition reads, set from element `elem`.
    fn set_last(&self, out: &mut Out, ty: &ValueType, elem: &str) {
        match ty {
            ValueType::Packet(n) | ValueType::Union(n) => {
                let v = self.locals.var(last_var(Some(n), Ty::Int), &type_name(n));
                out.line(format!("{} := {};", v, elem));
            }
            ValueType::Float { .. } => {
                let v = self.locals.var(last_var(None, Ty::Float), "Double");
                out.line(format!("{} := {};", v, elem));
            }
            _ => {
                let v = self.locals.var(last_var(None, Ty::Int), "Int64");
                out.line(format!("{} := Int64({});", v, elem));
            }
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if not {} then raise pbR.Error(pekConstraint, {});",
            self.scope.expr(cond),
            pas_string(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pbR.At({});", pas_string(field)));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        let place = self.scope.field(m);
        let sel = self.locals.var("pbSel", "Int64");
        out.line(format!("{} := {};", sel, self.scope.expr(selector)));
        out.line(format!("FreeAndNil({});", place));
        let mut first = true;
        for arm in arms.iter().filter(|a| !a.default) {
            let test = arm_test(arm, arms, "pbSel").unwrap_or_else(|| "True".into());
            out.line(format!("{}if {} then", if first { "" } else { "else " }, test));
            out.line(format!("  {} := {}", place, self.arm_value(u, arm)));
            first = false;
        }
        let otherwise = match arms.iter().find(|a| a.default) {
            Some(arm) => format!("{} := {};", place, self.arm_value(u, arm)),
            None => format!(
                "raise pbR.Error(pekInvalid, {} + IntToStr(pbSel));",
                pas_string(&format!("no arm of `{}` for ", m.name))
            ),
        };
        if first {
            out.line(otherwise);
        } else {
            out.line("else");
            out.line(format!("  {}", otherwise));
        }
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        let v = self.locals.var(format!("pb_win{}", id), "Int64");
        out.line(format!("{} := pbR.PushLimit({});", v, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pbR.PopLimit(pb_win{}, {});", id, Pascal::flag(exact)));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        let v = self.locals.var(mark_var(mark), "Int64");
        out.line(format!("{} := pbR.PositionBits;", v));
    }

    fn set_mark(&self, out: &mut Out, mark: Mark) {
        self.mark(out, mark);
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if Int64({}) <> {} then raise pbR.Error(pekMismatch, {});",
            self.scope.field(m),
            self.scope.expr(value),
            pas_string(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        let j = self.locals.var("pbJ", "TPbJump");
        let place = self.scope.field(m);
        out.line(format!("{} := pbR.Jump({}, {});", j, from, self.scope.expr(offset)));
        out.line(format!("FreeAndNil({});", place));
        out.line(format!(
            "{} := {}.DecodeFrom(pbR{});",
            place,
            type_name(&target.name),
            call_args(&self.scope, target)
        ));
        out.line("pbR.JumpBack(pbJ);");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pbR.SkipBits(PbPad(pbR.PositionBits - pb_start, {}));", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} := {};", self.scope.field(m), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "pbR.ReadCString".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pbR.ReadUntil({}, {})", byte_list(term), Pascal::flag(*optional))
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("pbR.ReadBytes(pbR.Count(Int64({}), 8))", read_elem(&self.scope, prefix, &PREFIX_LEN))
            }
            (_, Some(Count::Expr(e))) => format!("pbR.ReadBytes(pbR.Count({}, 8))", self.scope.expr(e)),
            _ => "pbR.ReadBytes(pbR.RemainingBits div 8)".to_string(),
        };
        let padded = Pascal::flag(*mode == StrMode::Padded);
        if m.encoding == TextEncoding::Utf8 {
            out.line(format!("{} := pbR.DecodeUtf8({}, {});", self.scope.field(m), raw, padded));
        } else {
            out.line(format!("{} := pbR.DecodeText({}, {}, {});", self.scope.field(m), raw, m.encoding.id(), padded));
        }
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pbR.SkipBits({});", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pbR.SkipBits(Int64(pbR.Count({}, {})) * {});", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("pbR.SkipBits(pbR.RemainingBits);"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.line(format!("if {} then", self.scope.expr(cond)));
        out.open("begin");
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("end;");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("pbR.SetVersion(Int64({}), {}, {});", self.scope.field(m), min, latest));
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        let place = self.scope.field(m);
        if let Codec::Packet(_) = codec {
            out.line(format!("FreeAndNil({});", place));
        }
        out.line(format!("{} := {};", place, read_elem(&self.scope, codec, ty)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = self.scope.field(m);
        let ebits = codec.min_elem_bits();
        let elem = read_elem(&self.scope, codec, ty);
        match count {
            Count::Expr(e) => {
                let n = format!("pbR.Count({}, {})", self.scope.expr(e), ebits);
                if ty.is_byte() {
                    out.line(format!("{} := pbR.ReadBytes({});", target, n));
                } else {
                    self.locals.var("pbN", "Integer");
                    self.locals.var("pbI", "Integer");
                    out.line(format!("pbN := {};", n));
                    out.line(format!("SetLength({}, pbN);", target));
                    out.line("for pbI := 0 to pbN - 1 do");
                    out.open("begin");
                    out.line("pbR.AtIndex(pbI);");
                    out.line(format!("{}[pbI] := {};", target, elem));
                    out.close("end;");
                }
            }
            Count::Terminated { term, optional } => {
                out.line(format!("{} := pbR.ReadUntil({}, {});", target, byte_list(term), Pascal::flag(*optional)))
            }
            Count::Remaining if ty.is_byte() => {
                out.line(format!("{} := pbR.ReadBytes(pbR.RemainingBits div 8);", target));
            }
            Count::Until(_) | Count::Remaining => {
                self.locals.var("pbN", "Integer");
                out.line("pbN := 0;");
                out.line(format!("SetLength({}, 0);", target));
                out.line("while pbR.RemainingBits > 0 do");
                out.open("begin");
                out.line("pbR.AtIndex(pbN);");
                self.grow(out, &target);
                out.line(format!("{}[pbN] := {};", target, elem));
                out.line("Inc(pbN);");
                if let Count::Until(cond) = count {
                    self.set_last(out, ty, &format!("{}[pbN - 1]", target));
                    out.line(format!("if {} then Break;", self.scope.expr(cond)));
                }
                out.close("end;");
                out.line(format!("SetLength({}, pbN);", target));
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, Pascal::little(endian)),
            _ => format!("pbR.ReadBits({})", container_width),
        };
        let c = self.locals.var("pbC", "UInt64");
        out.line(format!("{} := {};", c, raw));
        for part in parts {
            let m = self.scope.member(part.member);
            out.line(format!(
                "{} := {};",
                self.scope.field(m),
                bits_value(&m.ty, "pbC", part.shift, part.width, part.signed)
            ));
        }
    }
}
