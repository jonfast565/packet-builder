//! Rust decoder statements.

use super::expr::store_value;
use super::naming::{Rust, ident, scalar_type};
use crate::generators::common::union::variant_name;
use crate::generators::common::{Dialect, Mode, Out, PREFIX_LEN, Scope, StepEmitter, mark_var, mask, string_literal};
use crate::ir::{Arm, BitPart, Codec, Count, Mark, Member, Packet, PacketRef, StrMode, TExpr, TextEncoding, ValueType};

/// Expression that reads one element.
fn read_elem(scope: &Scope<'_, Rust>, codec: &Codec, ty: &ValueType) -> String {
    let st = scalar_type(ty);
    let signed = ty.is_signed();
    let width = match ty {
        ValueType::Int { width, .. } => *width,
        _ => 0,
    };
    let raw = match codec {
        Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
        Codec::Bits { width } => format!("pb_r.read_bits({})?", width),
        Codec::Float { width: 32, endian } => {
            return format!("f32::from_bits(pb_r.read_uint(4, {})? as u32)", Rust::little(endian));
        }
        Codec::Float { endian, .. } => return format!("f64::from_bits(pb_r.read_uint(8, {})?)", Rust::little(endian)),
        Codec::Mac => return "pb_r.read_mac()?".into(),
        Codec::Varint(k) => format!("pb_r.read_varint({})?", k.id()),
        Codec::Packet(r) => return format!("{}::decode_from(pb_r{})?", r.name, call_args(scope, r)),
        Codec::Str(_) => unreachable!("strings are handled by Decoder::string"),
    };
    if signed { format!("pb_sext({}, {}) as {}", raw, width, st) } else { format!("{} as {}", raw, st) }
}

/// `, a, b`: the arguments for nested packet `r`.
pub fn call_args(scope: &Scope<'_, Rust>, r: &PacketRef) -> String {
    scope.args(r, store_value).iter().map(|a| format!(", {}", a)).collect()
}

/// `[0x0d, 0x0a]`
pub fn byte_list(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}u8", b)).collect();
    format!("[{}]", items.join(", "))
}

pub struct Decoder<'a> {
    scope: Scope<'a, Rust>,
    /// Byte buffers and strings borrow the input (`Cow::Borrowed`).
    zero_copy: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(packet: &'a Packet, zero_copy: bool) -> Self {
        Decoder { scope: Scope::new(packet, Mode::Decode), zero_copy }
    }

    /// The reader method for `n` bytes: a copy, or a borrowed slice.
    fn read_bytes(&self) -> &'static str {
        if self.zero_copy { "read_slice" } else { "read_bytes" }
    }

    /// A byte buffer value from `read` (a slice when zero-copy).
    fn buffer(&self, read: String) -> String {
        if self.zero_copy { format!("Cow::Borrowed({})", read) } else { read }
    }

    /// Expression that decodes `arm` of union `u`.
    fn arm_value(&self, u: &str, arm: &Arm) -> String {
        let v = variant_name(arm);
        match (&arm.ty, &arm.codec, &arm.count) {
            (None, ..) => format!("{}::{}", u, v),
            (Some(_), _, Some(Count::Expr(e))) => {
                let read = format!("pb_r.{}(pb_r.count({}, 8)?)?", self.read_bytes(), self.scope.expr(e));
                format!("{}::{}({})", u, v, self.buffer(read))
            }
            (Some(_), _, Some(Count::Remaining)) => {
                let read = format!("pb_r.{}(pb_r.remaining_bits() / 8)?", self.read_bytes());
                format!("{}::{}({})", u, v, self.buffer(read))
            }
            (Some(ty), Some(codec), None) => format!("{}::{}({})", u, v, read_elem(&self.scope, codec, ty)),
            _ => format!("{}::{}(Default::default())", u, v),
        }
    }
}

impl StepEmitter for Decoder<'_> {
    fn packet(&self) -> &Packet {
        self.scope.packet
    }

    fn check(&self, out: &mut Out, cond: &TExpr, message: &str) {
        out.line(format!(
            "if !{} {{ return Err(pb_r.error(PbErrorKind::Constraint, {}.into())); }}",
            self.scope.expr(cond),
            string_literal(message)
        ));
    }

    fn locate(&self, out: &mut Out, field: &str) {
        out.line(format!("pb_r.at(\"{}\");", field));
    }

    fn switch(&self, out: &mut Out, m: &Member, selector: &TExpr, arms: &[Arm]) {
        let ValueType::Union(u) = &m.ty else { return };
        out.open("{");
        out.line(format!("let pb_sel: i64 = {};", self.scope.expr(selector)));
        out.open(format!("p.{} = match pb_sel {{", ident(&m.name)));
        for arm in arms.iter().filter(|a| !a.default) {
            let pat: Vec<String> = arm.values.iter().map(|v| v.to_string()).collect();
            out.line(format!("{} => {},", pat.join(" | "), self.arm_value(u, arm)));
        }
        match arms.iter().find(|a| a.default) {
            Some(arm) => out.line(format!("_ => {},", self.arm_value(u, arm))),
            None => out.line(format!(
                "_ => return Err(pb_r.error(PbErrorKind::Invalid, format!(\"no arm of `{}` for {{}}\", pb_sel))),",
                m.name
            )),
        }
        out.close("};");
        out.close("}");
    }

    fn open_window(&self, out: &mut Out, id: usize, size: Option<&TExpr>) {
        let size = size.map(|e| self.scope.expr(e)).unwrap_or_else(|| "0".into());
        out.line(format!("let pb_win{} = pb_r.push_limit({})?;", id, size));
    }

    fn close_window(&self, out: &mut Out, id: usize, _sized: bool, exact: bool) {
        out.line(format!("pb_r.pop_limit(pb_win{}, {})?;", id, exact));
    }

    fn mark(&self, out: &mut Out, mark: Mark) {
        out.line(format!("let {} = pb_r.position_bits();", mark_var(mark)));
    }

    fn verify(&self, out: &mut Out, m: &Member, value: &TExpr) {
        out.line(format!(
            "if (p.{} as i64) != {} {{ return Err(pb_r.error(PbErrorKind::Mismatch, {}.into())); }}",
            ident(&m.name),
            self.scope.expr(value),
            string_literal(&format!("`{}` does not match the value computed from the data", m.name))
        ));
    }

    fn at(&self, out: &mut Out, m: &Member, target: &PacketRef, offset: &TExpr, root: bool) {
        out.open("{");
        let from = if root { "0" } else { "pb_start" };
        out.line(format!("let pb_j = pb_r.jump({}, {})?;", from, self.scope.expr(offset)));
        out.line(format!(
            "p.{} = {}::decode_from(pb_r{})?;",
            ident(&m.name),
            target.name,
            call_args(&self.scope, target)
        ));
        out.line("pb_r.jump_back(pb_j);");
        out.close("}");
    }

    fn align(&self, out: &mut Out, bytes: u64) {
        out.line(format!("pb_r.skip_bits(pb_pad(pb_r.position_bits() - pb_start, {}))?;", bytes * 8))
    }

    fn calc(&self, out: &mut Out, m: &Member, e: &TExpr) {
        out.line(format!("p.{} = {};", ident(&m.name), store_value(self.scope.expr(e), &m.ty)));
    }

    fn string(&self, out: &mut Out, m: &Member, mode: &StrMode, array: Option<&Count>) {
        let zc = if self.zero_copy { "_slice" } else { "" };
        let rb = self.read_bytes();
        let raw = match (mode, array) {
            (StrMode::CString, _) => format!("pb_r.read_cstring{}()?", zc),
            (StrMode::Terminated { term, optional }, _) => {
                format!("pb_r.read_until{}(&{}, {})?", zc, byte_list(term), optional)
            }
            (StrMode::Prefixed { prefix, .. }, _) => {
                let len = read_elem(&self.scope, prefix, &PREFIX_LEN);
                format!("{{ let pb_n = {} as i64; pb_r.{}(pb_r.count(pb_n, 8)?)? }}", len, rb)
            }
            (_, Some(Count::Expr(e))) => format!("pb_r.{}(pb_r.count({}, 8)?)?", rb, self.scope.expr(e)),
            _ => format!("pb_r.{}(pb_r.remaining_bits() / 8)?", rb),
        };
        let padded = *mode == StrMode::Padded;
        out.open("{");
        if self.zero_copy {
            out.line(format!("let pb_t = {};", raw));
            if m.encoding == TextEncoding::Utf8 {
                out.line(format!("p.{} = Cow::Borrowed(pb_r.utf8_slice(pb_t, {})?);", ident(&m.name), padded));
            } else {
                out.line(format!(
                    "p.{} = Cow::Owned(pb_r.text(pb_t.to_vec(), {}, {})?);",
                    ident(&m.name),
                    m.encoding.id(),
                    padded
                ));
            }
            out.close("}");
            return;
        }
        if m.encoding == TextEncoding::Utf8 {
            let raw = if padded { format!("pb_until_nul({})", raw) } else { raw };
            out.line(format!("let pb_t = {};", raw));
            out.line(format!("p.{} = pb_r.utf8(pb_t)?;", ident(&m.name)));
        } else {
            out.line(format!("let pb_t = {};", raw));
            out.line(format!("p.{} = pb_r.text(pb_t, {}, {})?;", ident(&m.name), m.encoding.id(), padded));
        }
        out.close("}");
    }

    fn padding(&self, out: &mut Out, codec: &Codec, array: Option<&Count>) {
        let bits = codec.bits();
        match array {
            None => out.line(format!("pb_r.skip_bits({})?;", bits)),
            Some(Count::Expr(e)) => {
                out.line(format!("pb_r.skip_bits(pb_r.count({}, {})? * {})?;", self.scope.expr(e), bits, bits));
            }
            Some(Count::Remaining) => out.line("pb_r.skip_bits(pb_r.remaining_bits())?;"),
            // Padding cannot use `until` or `term` (rejected by the analysis).
            Some(Count::Until(_) | Count::Terminated { .. }) => {}
        }
    }

    fn scalar(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec) {
        let read = read_elem(&self.scope, codec, ty);
        // A re-declaration narrower than the member (`@3 count uint32`).
        let read = if &m.ty != ty { format!("({}) as {}", read, scalar_type(&m.ty)) } else { read };
        out.line(format!("p.{} = {};", ident(&m.name), read));
    }

    fn open_gate(&self, out: &mut Out, cond: &TExpr) {
        out.open(format!("if {} {{", self.scope.expr(cond)));
    }

    fn close_gate(&self, out: &mut Out) {
        out.close("}");
    }

    fn adopt_version(&self, out: &mut Out, m: &Member) {
        let (min, latest) = self.scope.packet.version_bounds();
        out.line(format!("pb_r.set_version(p.{} as i64, {}, {})?;", ident(&m.name), min, latest));
    }

    fn array(&self, out: &mut Out, m: &Member, ty: &ValueType, codec: &Codec, count: &Count) {
        let target = format!("p.{}", ident(&m.name));
        let ebits = codec.min_elem_bits();
        let n = match count {
            Count::Expr(e) => format!("pb_r.count({}, {})?", self.scope.expr(e), ebits),
            Count::Terminated { term, optional } => {
                let zc = if self.zero_copy { "_slice" } else { "" };
                let read = format!("pb_r.read_until{}(&{}, {})?", zc, byte_list(term), optional);
                out.line(format!("{} = {};", target, self.buffer(read)));
                return;
            }
            Count::Until(cond) if self.zero_copy && ty.is_byte() => {
                // Built byte by byte: owned.
                out.open("{");
                out.line("let mut pb_v: Vec<u8> = Vec::new();");
                out.open("while pb_r.remaining_bits() > 0 {");
                out.line("pb_r.at_index(pb_v.len());");
                out.line(format!("let pb_last = {};", read_elem(&self.scope, codec, ty)));
                out.line(format!("let pb_stop = {};", self.scope.expr(cond)));
                out.line("pb_v.push(pb_last);");
                out.line("if pb_stop { break; }");
                out.close("}");
                out.line(format!("{} = Cow::Owned(pb_v);", target));
                out.close("}");
                return;
            }
            Count::Until(cond) => {
                out.open("while pb_r.remaining_bits() > 0 {");
                out.line(format!("pb_r.at_index({}.len());", target));
                out.line(format!("let pb_last = {};", read_elem(&self.scope, codec, ty)));
                out.line(format!("let pb_stop = {};", self.scope.expr(cond)));
                out.line(format!("{}.push(pb_last);", target));
                out.line("if pb_stop { break; }");
                out.close("}");
                return;
            }
            Count::Remaining => String::new(),
        };
        if ty.is_byte() {
            let read = match count {
                Count::Expr(_) => format!("pb_r.{}({})?", self.read_bytes(), n),
                _ => format!("pb_r.{}(pb_r.remaining_bits() / 8)?", self.read_bytes()),
            };
            out.line(format!("{} = {};", target, self.buffer(read)));
            return;
        }
        match count {
            Count::Expr(_) => {
                out.open("{");
                out.line(format!("let pb_n = {};", n));
                out.line(format!("{} = Vec::with_capacity(pb_n);", target));
                out.open("for pb_i in 0..pb_n {");
                out.line("pb_r.at_index(pb_i);");
                out.line(format!("{}.push({});", target, read_elem(&self.scope, codec, ty)));
                out.close("}");
                out.close("}");
            }
            _ => {
                out.open("while pb_r.remaining_bits() > 0 {");
                out.line(format!("pb_r.at_index({}.len());", target));
                out.line(format!("{}.push({});", target, read_elem(&self.scope, codec, ty)));
                out.close("}");
            }
        }
    }

    fn bitfield(&self, out: &mut Out, container: &Codec, container_width: u32, parts: &[BitPart]) {
        out.open("{");
        let raw = match container {
            Codec::Bytes { nbytes, endian } => format!("pb_r.read_uint({}, {})?", nbytes, Rust::little(endian)),
            _ => format!("pb_r.read_bits({})?", container_width),
        };
        out.line(format!("let pb_c: u64 = {};", raw));
        for part in parts {
            let m = self.scope.member(part.member);
            let st = scalar_type(&m.ty);
            let bits = format!("((pb_c >> {}) & 0x{:x})", part.shift, mask(part.width));
            let value = if part.signed {
                format!("pb_sext({}, {}) as {}", bits, part.width, st)
            } else {
                format!("{} as {}", bits, st)
            };
            out.line(format!("p.{} = {};", ident(&m.name), value));
        }
        out.close("}");
    }
}
