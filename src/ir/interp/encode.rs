//! Encoding by walking a packet's steps.

use super::eval::{Env, eval, store};
use super::rt::{PbError, PbErrorKind, PbWriter};
use super::value::{Struct, Value};
use super::{arguments, check, checked_members, gate_end, intern, pad, versions};
use crate::ast::Endianness;
use std::cell::RefCell;
use std::collections::HashMap;

use crate::ir::{BitPart, Codec, Count, Mark, Module, Packet, Step, StrMode, TextEncoding, ValueType};

/// Encode `value`, a packet named `name`. Members missing from the value
/// count as zero.
pub fn encode(module: &Module, name: &str, value: &Value) -> Result<Vec<u8>, PbError> {
    encode_version(module, name, value, None)
}

/// Encode as protocol `version` (None: the version the value carries
/// in-band, or the latest).
pub fn encode_version(module: &Module, name: &str, value: &Value, version: Option<u32>) -> Result<Vec<u8>, PbError> {
    let mut w = PbWriter::new();
    if let Some(v) = version {
        let (min, latest) = versions(module);
        w.set_version(v as i64, min, latest)?;
    }
    let p = find(module, name, &w)?;
    let s = match value {
        Value::Struct(s) => s.clone(),
        _ => return Err(w.error(PbErrorKind::Invalid, format!("a value of packet `{}` must be a struct", name))),
    };
    if !p.params.is_empty() {
        let msg = format!("packet `{}` takes {} argument(s); encode the packet containing it", name, p.params.len());
        return Err(w.error(PbErrorKind::Invalid, msg));
    }
    Encoder { module, params: RefCell::new(Vec::new()), version: RefCell::new(0) }.packet(p, &s, &mut w)?;
    w.finish()
}

fn find<'m>(module: &'m Module, name: &str, w: &PbWriter) -> Result<&'m Packet, PbError> {
    module
        .packets
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| w.error(PbErrorKind::Invalid, format!("unknown packet `{}`", name)))
}

fn little(e: &Endianness) -> bool {
    *e == Endianness::Le
}

struct Encoder<'m> {
    module: &'m Module,
    /// The arguments of the packet being encoded.
    params: RefCell<Vec<i64>>,
    /// The writer's protocol version, for expressions.
    version: RefCell<i64>,
}

impl Encoder<'_> {
    fn env<'v>(&self, values: &'v [Value]) -> Env<'v> {
        Env { version: *self.version.borrow(), ..Env::new(values, &self.params.borrow()) }
    }

    fn packet_with(&self, p: &Packet, s: &Struct, args: Vec<i64>, w: &mut PbWriter) -> Result<(), PbError> {
        let outer = self.params.replace(args);
        self.packet(p, s, w)?;
        self.params.replace(outer);
        Ok(())
    }

    fn packet(&self, p: &Packet, s: &Struct, w: &mut PbWriter) -> Result<(), PbError> {
        w.enter(intern(&p.name))?;
        let (min, latest) = versions(self.module);
        self.version.replace(w.version_or(latest));
        let mut values: Vec<Value> = p
            .members
            .iter()
            .map(|m| s.get(&m.name).cloned().unwrap_or_else(|| Value::default_for(self.module, m)))
            .collect();
        // The version the value carries in-band, before anything uses it.
        if let Some(vm) = p.version_member {
            let v = match values[vm] {
                Value::Int(v) => v as i64,
                _ => 0,
            };
            w.adopt_version(v, min, latest)?;
            self.version.replace(w.version_or(latest));
            values[vm] = Value::Int(w.version_or(latest) as i128);
        }
        // Calculated members that lengths depend on are recomputed, as in
        // generated encoders.
        for (m, e) in p.encode_calc_members() {
            let idx = p.members.iter().position(|x| x.name == m.name).expect("member");
            let v = eval(e, &self.env(&values));
            // Derived values are range-checked when written, so keep them whole.
            values[idx] = if m.is_derived() { Value::Int(v.int() as i128) } else { store(v, &m.ty) };
        }
        let start = w.position_bits();
        let mut marks = HashMap::from([(Mark::PacketStart, start)]);
        let mut windows: HashMap<usize, (usize, Option<i64>)> = HashMap::new();
        let mut i = 0;
        while i < p.steps.len() {
            let step = &p.steps[i];
            for mi in checked_members(step).into_iter().filter(|m| !p.patches.contains(m)) {
                for c in p.members[mi].enforced_checks() {
                    w.at(intern(self.field_name(p, step)));
                    check(&c.cond, &c.message, &self.env(&values), |m| w.error(PbErrorKind::Constraint, m))?;
                }
            }
            marks.insert(Mark::Before(i), w.position_bits());
            match step {
                Step::OpenGate { cond, .. } => {
                    if !eval(cond, &self.env(&values)).bool() {
                        i = gate_end(p, i);
                    }
                }
                Step::CloseGate { .. } => {}
                Step::OpenWindow { size, .. } => {
                    if let Some(name) = p.steps.get(i + 1).and_then(|s| super::decode::step_name(p, s)) {
                        w.at(intern(name));
                    }
                    // A size only known after encoding the body is not checked.
                    let n = (!p.depends_on_wire(size)).then(|| self.expr(&values, size));
                    windows.insert(i, (w.position_bits(), n));
                }
                Step::CloseWindow { open, exact } => {
                    if let Some(name) = p.steps.get(open + 1).and_then(|s| super::decode::step_name(p, s)) {
                        w.at(intern(name));
                    }
                    if let Some((start, Some(n))) = windows.remove(open) {
                        w.end_window(start, n, *exact)?;
                    }
                }
                _ => self.step(p, step, &values, start, w)?,
            }
            marks.insert(Mark::After(i), w.position_bits());
            i += 1;
        }
        marks.insert(Mark::PacketEnd, w.position_bits());
        // Fields derived from the encoded bytes: compute, check, patch.
        for &mi in &p.patches {
            let m = &p.members[mi];
            let (Some(si), Some(e)) = (p.field_step(mi), m.derived_expr()) else { continue };
            let Step::Field { codec, ty, .. } = &p.steps[si] else { continue };
            w.at(intern(&m.name));
            let v = {
                let wr: &PbWriter = w;
                let sum = |a, f, t, hf, ht| wr.checksum(a, f, t, hf, ht);
                eval(e, &Env { marks: Some(&marks), checksum: Some(&sum), ..self.env(&values) }).int()
            };
            values[mi] = Value::Int(v as i128);
            for c in m.enforced_checks() {
                check(&c.cond, &c.message, &self.env(&values), |msg| w.error(PbErrorKind::Constraint, msg))?;
            }
            let raw = int_bits(ty, &values[mi], w)?;
            let at = marks[&Mark::Before(si)];
            match codec {
                Codec::Bytes { nbytes, endian } => w.patch_uint(at, raw, *nbytes, little(endian)),
                _ => w.patch_bits(at, raw, codec.bits()),
            }
        }
        w.leave();
        Ok(())
    }

    /// The name errors report for a step's field.
    fn field_name<'p>(&self, p: &'p Packet, step: &'p Step) -> &'p str {
        match step {
            Step::Field { member: Some(mi), .. } => &p.members[*mi].name,
            Step::Bitfield { name, .. } => name,
            _ => "_",
        }
    }

    fn expr(&self, values: &[Value], e: &crate::ir::TExpr) -> i64 {
        eval(e, &self.env(values)).int()
    }

    fn step(&self, p: &Packet, step: &Step, values: &[Value], start: usize, w: &mut PbWriter) -> Result<(), PbError> {
        match step {
            Step::Align { bytes } => {
                w.write_zero_bits(pad(w.position_bits() - start, *bytes as usize * 8));
                Ok(())
            }
            Step::Calc { .. } => Ok(()),
            Step::Assert { index } if p.depends_on_wire(&p.asserts[*index].cond) => Ok(()),
            Step::Assert { index } => {
                w.at("");
                let a = &p.asserts[*index];
                check(&a.cond, &a.message, &self.env(values), |m| w.error(PbErrorKind::Constraint, m))
            }
            Step::Field { member, codec, array, ty } => {
                let name = member.map(|i| p.members[i].name.as_str()).unwrap_or("_");
                w.at(intern(name));
                // A length only known after encoding the body is not checked.
                let array = &match array {
                    Some(Count::Expr(e)) if member.is_some() && p.depends_on_wire(e) => Some(Count::Remaining),
                    a => a.clone(),
                };
                match (member, codec) {
                    (Some(mi), Codec::Str(mode)) => {
                        let enc = p.members[*mi].encoding;
                        self.string(values, &values[*mi], mode, array.as_ref(), enc, w)
                    }
                    (None, codec) => {
                        let bits = codec.bits() as usize;
                        match array {
                            None => w.write_zero_bits(bits),
                            Some(Count::Expr(e)) => w.write_zero_bits(self.expr(values, e).max(0) as usize * bits),
                            Some(Count::Remaining | Count::Until(_) | Count::Terminated { .. }) => {}
                        }
                        Ok(())
                    }
                    (Some(mi), codec) if array.is_none() && p.patches.contains(mi) => {
                        // A placeholder, patched after the last step.
                        w.write_zero_bits(codec.bits() as usize);
                        Ok(())
                    }
                    (Some(mi), codec) => match array {
                        None => self.elem(values, codec, ty, &values[*mi], w),
                        Some(count) => self.array(values, &values[*mi], ty, codec, count, w),
                    },
                }
            }
            Step::Bitfield { name, container, container_width, parts } => {
                w.at(intern(name));
                self.bitfield(values, container, *container_width, parts, w)
            }
            Step::Switch { member, selector, arms } => {
                let m = &p.members[*member];
                w.at(intern(&m.name));
                let Value::Variant { arm: held, value } = &values[*member] else {
                    return Err(w.error(PbErrorKind::Invalid, format!("`{}` holds no arm", m.name)));
                };
                let Some(arm) = arms.iter().find(|a| &a.name == held) else {
                    return Err(w.error(PbErrorKind::Invalid, format!("`{}` has no arm `{}`", m.name, held)));
                };
                let sel = self.expr(values, selector);
                let picks =
                    if arm.default { !arms.iter().any(|a| a.values.contains(&sel)) } else { arm.values.contains(&sel) };
                if !picks {
                    return Err(w.error(
                        PbErrorKind::Mismatch,
                        format!("`{}` holds arm `{}`, but its selector is {}", m.name, arm.name, sel),
                    ));
                }
                match (&arm.ty, &arm.codec, &arm.count, value) {
                    (Some(_), _, Some(count), Some(v)) => {
                        let b = match v.as_ref() {
                            Value::Bytes(b) => b.clone(),
                            _ => Vec::new(),
                        };
                        if let Count::Expr(e) = count
                            && !p.depends_on_wire(e)
                        {
                            w.check_len(b.len(), self.expr(values, e))?;
                        }
                        w.write_bytes(&b);
                        Ok(())
                    }
                    (Some(ty), Some(codec), None, Some(v)) => self.elem(values, codec, ty, v, w),
                    _ => Ok(()),
                }
            }
            Step::At { member, target, offset, root } => {
                let m = &p.members[*member];
                w.at(intern(&m.name));
                let mut sub = w.sub(start, self.expr(values, offset), *root)?;
                self.elem(values, &Codec::Packet(target.clone()), &m.ty, &values[*member], &mut sub)?;
                w.place(sub);
                Ok(())
            }
            Step::OpenWindow { .. } | Step::CloseWindow { .. } | Step::OpenGate { .. } | Step::CloseGate { .. } => {
                Ok(())
            }
        }
    }

    fn elem(
        &self,
        values: &[Value],
        codec: &Codec,
        ty: &ValueType,
        v: &Value,
        w: &mut PbWriter,
    ) -> Result<(), PbError> {
        match codec {
            Codec::Bytes { nbytes, endian } => {
                let raw = int_bits(ty, v, w)?;
                w.write_uint(raw, *nbytes, little(endian));
            }
            Codec::Bits { width } => {
                let raw = int_bits(ty, v, w)?;
                w.write_bits(raw, *width);
            }
            Codec::Float { width, endian } => {
                let f = match v {
                    Value::Float(f) => *f,
                    Value::Int(i) => *i as f64,
                    _ => 0.0,
                };
                if *width == 32 {
                    w.write_uint((f as f32).to_bits() as u64, 4, little(endian));
                } else {
                    w.write_uint(f.to_bits(), 8, little(endian));
                }
            }
            Codec::Varint(kind) => {
                let raw = int_bits(ty, v, w)?;
                w.write_varint(kind.id(), raw)?;
            }
            Codec::Mac => match v {
                Value::Bytes(b) if b.len() == 6 => w.write_bytes(b),
                _ => return Err(w.error(PbErrorKind::Range, "a MAC address needs 6 bytes".into())),
            },
            Codec::Packet(target) => {
                let p = find(self.module, &target.name, w)?;
                let s = match v {
                    Value::Struct(s) => s.clone(),
                    _ => Struct::default_for(self.module, p),
                };
                let args = arguments(self.module, target, &self.env(values));
                self.packet_with(p, &s, args, w)?;
            }
            Codec::Str(_) => unreachable!("strings are encoded by Encoder::string"),
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn array(
        &self,
        values: &[Value],
        v: &Value,
        ty: &ValueType,
        codec: &Codec,
        count: &Count,
        w: &mut PbWriter,
    ) -> Result<(), PbError> {
        let items: Vec<Value> = match v {
            Value::List(items) => items.clone(),
            Value::Bytes(b) => b.iter().map(|x| Value::Int(*x as i128)).collect(),
            _ => Vec::new(),
        };
        if let Count::Expr(e) = count {
            w.check_len(items.len(), self.expr(values, e))?;
        }
        if let Count::Terminated { term, .. } = count {
            let b: Vec<u8> = items.iter().map(|x| if let Value::Int(i) = x { *i as u8 } else { 0 }).collect();
            w.check_no_term(&b, term)?;
            w.write_bytes(&b);
            w.write_bytes(term);
            return Ok(());
        }
        for (i, item) in items.iter().enumerate() {
            w.at_index(i);
            self.elem(values, codec, ty, item, w)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn string(
        &self,
        values: &[Value],
        v: &Value,
        mode: &StrMode,
        array: Option<&Count>,
        enc: TextEncoding,
        w: &mut PbWriter,
    ) -> Result<(), PbError> {
        let text = match v {
            Value::Str(s) => s.clone(),
            _ => String::new(),
        };
        let encoded = w.text(&text, enc.id())?;
        let b = encoded.as_slice();
        match (mode, array) {
            (StrMode::CString, _) => {
                w.check_no_nul(b)?;
                w.write_bytes(b);
                w.write_bytes(&[0]);
            }
            (StrMode::Terminated { term, .. }, _) => {
                w.check_no_term(b, term)?;
                w.write_bytes(b);
                w.write_bytes(term);
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                w.check_u(b.len() as u64, *width)?;
                let len = Value::Int(b.len() as i128);
                self.elem(values, prefix, &ValueType::Int { width: 64, signed: false }, &len, w)?;
                w.write_bytes(b);
            }
            (StrMode::Padded, Some(Count::Expr(e))) => {
                let n = self.expr(values, e);
                w.check_fits(b.len(), n)?;
                w.write_bytes(b);
                w.write_zero_bits((n as usize - b.len()) * 8);
            }
            (_, Some(Count::Expr(e))) => {
                w.check_len(b.len(), self.expr(values, e))?;
                w.write_bytes(b);
            }
            _ => w.write_bytes(b),
        }
        Ok(())
    }

    fn bitfield(
        &self,
        values: &[Value],
        container: &Codec,
        container_width: u32,
        parts: &[BitPart],
        w: &mut PbWriter,
    ) -> Result<(), PbError> {
        let mut c = 0u64;
        for part in parts {
            let ty = ValueType::Int { width: part.width, signed: part.signed };
            let raw = int_bits(&ty, &values[part.member], w)?;
            c |= (raw & crate::generators::common::mask(part.width)) << part.shift;
        }
        match container {
            Codec::Bytes { nbytes, endian } => w.write_uint(c, *nbytes, little(endian)),
            _ => w.write_bits(c, container_width),
        }
        Ok(())
    }
}

/// The two's complement bits of an integer value after checking that it
/// fits the member type (the storage type in generated code, and the logical
/// width where that is narrower).
fn int_bits(ty: &ValueType, v: &Value, w: &PbWriter) -> Result<u64, PbError> {
    let v = match v {
        Value::Int(i) => *i,
        Value::Float(f) => *f as i128,
        _ => 0,
    };
    let ValueType::Int { width, signed } = ty else { return Ok(v as u64) };
    let (lo, hi) =
        if *signed { (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1) } else { (0, (1i128 << width) - 1) };
    if v < lo || v > hi {
        let what = if *signed { "signed bit(s)" } else { "bit(s)" };
        return Err(w.error(PbErrorKind::Range, format!("value {} does not fit in {} {}", v, width, what)));
    }
    Ok(v as u64)
}
