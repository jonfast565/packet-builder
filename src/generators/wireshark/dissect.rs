//! Lua dissect statements: decode like the other backends, and add each
//! value to the protocol tree (`t`) as it is read. Checks, assertions and
//! derived fields that do not hold become expert warnings, not errors.

use super::expr::store_value;
use super::naming::{Lua, dissect_fn, field_key};
use crate::generators::common::union::{PY_LOGIC, arm_test};
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// A Lua string literal holding these bytes (`"\x0d\x0a"`).
pub fn byte_string(bytes: &[u8]) -> String {
    let items: String = bytes.iter().map(|b| format!("\\x{:02x}", b)).collect();
    format!("\"{}\"", items)
}

/// `, a, b`: the arguments for nested packet `r`.
fn call_args(scope: &Scope<'_, Lua>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// Expression reading one element; nested packets go under `tree` with
/// `label` (a Lua expression).
fn read_elem(scope: &Scope<'_, Lua>, codec: &Codec, ty: &ValueType, tree: &str, label: &str) -> String {
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("r:read_uint({}, {})", nbytes, Lua::little(endian)),
        Codec::Bits { width } => format!("r:read_bits({})", width),
        Codec::Float { width, endian } => return format!("r:read_float({}, {})", width, Lua::little(endian)),
        Codec::Mac => return "r:read_bytes(6)".into(),
        Codec::Varint(k) => return format!("r:read_varint({})", k.id()),
        Codec::Packet(r) => {
            return format!("{}(c, {}, {}{})", dissect_fn(&r.name), tree, label, call_args(scope, r));
        }
        Codec::Str(_) => unreachable!("strings are handled by Dissector::string"),
    };
    match ty {
        ValueType::Int { width, signed: true } => format!("pb_sext({}, {})", raw, width),
        _ => raw,
    }
}

pub struct Dissector<'a> {
    pub scope: Scope<'a, Lua>,
}

impl<'a> Dissector<'a> {
    pub fn new(packet: &'a Packet) -> Self {
        Dissector { scope: Scope::new(packet, Mode::Decode) }
    }

    fn key(&self, m: &Member) -> String {
        field_key(&self.scope.packet.name, &m.name)
    }

    fn place(&self, m: &Member) -> String {
        self.scope.field(m)
    }

    /// Statements that decode arm `arm` of member `m` (union `u`).
    fn arm(&self, out: &mut Out, m: &Member, u: &str, arm: &Arm) {
        let place = self.place(m);
        let kind = string_literal(&arm.name);
        let key = field_key(u, &arm.name);
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => {
                out.line(format!("{} = {{ kind = {} }}", place, kind));
                out.line(format!("pb_text(c, t, {})", string_literal(&format!("{}: {}", m.name, arm.name))));
            }
            (Some(_), _, Some(count)) => {
                let n = match count {
                    Count::Expr(e) => format!("r:count({}, 8)", self.scope.expr(e)),
                    _ => "r:remaining() // 8".into(),
                };
                out.line("pb_s = r.pos");
                out.line(format!("pb_v = r:read_bytes({})", n));
                out.line(format!("pb_add(c, t, {}, pb_s, pb_v)", key));
                out.line(format!("{} = {{ kind = {}, value = pb_v }}", place, kind));
            }
            (Some(ValueType::Packet(_)), Some(codec), None) => {
                let label = string_literal(&format!("{} ({})", m.name, arm.name));
                let v = read_elem(&self.scope, codec, &ValueType::Packet(String::new()), "t", &label);
                out.line(format!("{} = {{ kind = {}, value = {} }}", place, kind, v));
            }
            (Some(ty), Some(codec), None) => {
                out.line("pb_s = r.pos");
                out.line(format!("pb_v = {}", read_elem(&self.scope, codec, ty, "t", "nil")));
                out.line(format!("pb_add(c, t, {}, pb_s, pb_v)", key));
                out.line(format!("{} = {{ kind = {}, value = pb_v }}", place, kind));
            }
            _ => {}
        }
    }

    /// The loop body adding one element to array `m` (under subtree `pb_t`).
    fn element(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, index_var: &str) {
        let place = self.place(m);
        out.line(format!("r:at_index({})", index_var));
        out.line("pb_s = r.pos");
        let label = format!("\"[\" .. {} .. \"]\"", index_var);
        out.line(format!("pb_v = {}", read_elem(&self.scope, codec, ty, "pb_t", &label)));
        out.line(format!("{}[#{} + 1] = pb_v", place, place));
        if !matches!(codec, Codec::Packet(_)) && !ty.is_byte() {
            out.line(format!("pb_add(c, pb_t, {}, pb_s, pb_v)", self.key(m)));
        }
    }
}

impl StepEmitter for Dissector<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!("pb_check(c, t, {}, {})", self.scope.expr(cond), string_literal(message)));
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
            None => {
                out.line(format!("r:fail(\"invalid\", \"no arm of `{}` for \" .. pb_sel)", m.name.replace('"', "")))
            }
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
            "pb_verify(c, t, {}, {}, {})",
            string_literal(&m.name),
            self.place(m),
            self.scope.expr(value)
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("pb_j = r:jump({}, {})", from, self.scope.expr(offset)));
        out.line(format!(
            "{} = {}(c, t, {}{})",
            self.place(m),
            dissect_fn(&target.name),
            string_literal(&m.name),
            call_args(&self.scope, target)
        ));
        out.line("r:jump_back(pb_j)");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("r:skip_bits(pb_pad(r.pos - pb_start, {}))", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("{} = {}", self.place(m), store_value(self.scope.expr(e), &m.ty)));
        out.line(format!("pb_gen(c, t, {}, {})", self.key(m), self.place(m)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let raw = match (mode, array) {
            (StrMode::CString, _) => "r:read_cstring()".to_string(),
            (StrMode::Terminated { term, optional }, _) => {
                format!("r:read_until({}, {})", byte_string(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                format!("r:read_bytes(r:count({}, 8))", read_elem(&self.scope, prefix, &PREFIX_LEN, "t", "nil"))
            }
            (_, Some(Count::Expr(e))) => format!("r:read_bytes(r:count({}, 8))", self.scope.expr(e)),
            _ => "r:read_bytes(r:remaining() // 8)".to_string(),
        };
        let padded = *mode == StrMode::Padded;
        let enc = if m.encoding == TextEncoding::Utf8 { 0 } else { m.encoding.id() };
        out.line("pb_s = r.pos");
        out.line(format!("{} = r:text({}, {}, {})", self.place(m), raw, enc, padded));
        out.line(format!("pb_add(c, t, {}, pb_s, {})", self.key(m), self.place(m)));
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("r:skip_bits({})", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("r:skip_bits(r:count({}, {}) * {})", self.scope.expr(e), bits, bits))
            }
            Some(Count::Remaining) => out.line("r:skip_bits(r:remaining())"),
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
        if matches!(codec, Codec::Packet(_)) {
            let label = string_literal(&m.name);
            out.line(format!("{} = {}", self.place(m), read_elem(&self.scope, codec, ty, "t", &label)));
            return;
        }
        out.line("pb_s = r.pos");
        out.line(format!("{} = {}", self.place(m), read_elem(&self.scope, codec, ty, "t", "nil")));
        out.line(format!("pb_add(c, t, {}, pb_s, {})", self.key(m), self.place(m)));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let place = self.place(m);
        let ebits = codec.min_elem_bits();
        if ty.is_byte() && !matches!(count, Count::Until(_)) {
            let raw = match count {
                Count::Expr(e) => format!("r:read_bytes(r:count({}, 8))", self.scope.expr(e)),
                Count::Terminated { term, optional } => format!("r:read_until({}, {})", byte_string(term), optional),
                _ => "r:read_bytes(r:remaining() // 8)".into(),
            };
            out.line("pb_s = r.pos");
            out.line(format!("{} = {}", place, raw));
            out.line(format!("pb_add(c, t, {}, pb_s, {})", self.key(m), place));
            return;
        }
        out.line(format!("{} = {{}}", place));
        out.line("pb_a = r.pos");
        if ty.is_byte() {
            out.line("pb_t = nil");
        } else {
            out.line(format!("pb_t = pb_subtree(c, t, {})", string_literal(&m.name)));
        }
        match count {
            Count::Expr(e) => {
                out.line(format!("pb_n = r:count({}, {})", self.scope.expr(e), ebits));
                out.open("for pb_i = 0, pb_n - 1 do");
                self.element(out, m, ty, codec, "pb_i");
                out.close("end");
            }
            Count::Until(cond) => {
                out.open("while r:remaining() > 0 do");
                self.element(out, m, ty, codec, &format!("#{}", place));
                out.line("pb_last = pb_v");
                out.line(format!("if {} then break end", self.scope.expr(cond)));
                out.close("end");
            }
            _ => {
                out.open("while r:remaining() > 0 do");
                self.element(out, m, ty, codec, &format!("#{}", place));
                out.close("end");
            }
        }
        out.line("pb_close(c, pb_t, pb_a)");
        if ty.is_byte() {
            // Byte arrays are strings, as everywhere else.
            out.line(format!("{} = string.char(table.unpack({}))", place, place));
            out.line(format!("pb_add(c, t, {}, pb_a, {})", self.key(m), place));
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("r:read_uint({}, {})", nbytes, Lua::little(endian)),
            _ => format!("r:read_bits({})", container_width),
        };
        out.line("pb_s = r.pos");
        out.line(format!("pb_c = {}", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let bits = format!("((pb_c >> {}) & 0x{:x})", part.shift, mask(part.width));
            let v = if part.signed { format!("pb_sext({}, {})", bits, part.width) } else { bits };
            out.line(format!("{} = {}", self.place(m), v));
            out.line(format!("pb_add(c, t, {}, pb_s, {})", self.key(m), self.place(m)));
        }
    }
}
