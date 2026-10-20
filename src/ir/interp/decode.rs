//! Decoding by walking a packet's steps.

use super::eval::{Env, eval, store};
use super::rt::{PbError, PbErrorKind, PbReader};
use super::value::{Struct, Value};
use super::{arguments, check, checked_members, intern, pad, sext};
use std::collections::HashMap;

use crate::ir::{BitPart, Codec, Count, Mark, Module, Packet, Step, StrMode, TextEncoding, ValueType};

/// Decode packet `name` from the start of `data`; trailing bytes are ignored.
pub fn decode(module: &Module, name: &str, data: &[u8]) -> Result<Value, PbError> {
    let mut r = PbReader::new(data);
    decode_from(module, name, &mut r)
}

/// Decode packet `name` at the reader's position. Packets with parameters
/// can only be decoded inside another packet.
pub fn decode_from(module: &Module, name: &str, r: &mut PbReader) -> Result<Value, PbError> {
    let p = find(module, name, r)?;
    if !p.params.is_empty() {
        let msg = format!("packet `{}` takes {} argument(s); decode the packet containing it", name, p.params.len());
        return Err(r.error(PbErrorKind::Invalid, msg));
    }
    Ok(Value::Struct(Decoder { module, r, params: Vec::new() }.packet(p, Vec::new())?))
}

fn find<'m>(module: &'m Module, name: &str, r: &PbReader) -> Result<&'m Packet, PbError> {
    module
        .packets
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| r.error(PbErrorKind::Invalid, format!("unknown packet `{}`", name)))
}

struct Decoder<'m, 'r, 'd> {
    module: &'m Module,
    r: &'r mut PbReader<'d>,
    /// The arguments of the packet being decoded.
    params: Vec<i64>,
}

impl Decoder<'_, '_, '_> {
    fn env<'v>(&self, values: &'v [Value]) -> Env<'v> {
        Env::new(values, &self.params)
    }

    fn packet(&mut self, p: &Packet, args: Vec<i64>) -> Result<Struct, PbError> {
        let outer = std::mem::replace(&mut self.params, args);
        let s = self.packet_body(p)?;
        self.params = outer;
        Ok(s)
    }

    fn packet_body(&mut self, p: &Packet) -> Result<Struct, PbError> {
        self.r.enter(intern(&p.name))?;
        let mut values: Vec<Value> = p.members.iter().map(|m| Value::default_for(self.module, m)).collect();
        let start = self.r.position_bits();
        let mut marks = HashMap::from([(Mark::PacketStart, start)]);
        let mut windows = HashMap::new();
        for (i, step) in p.steps.iter().enumerate() {
            marks.insert(Mark::Before(i), self.r.position_bits());
            match step {
                Step::OpenWindow { size, .. } => {
                    if let Some(name) = p.steps.get(i + 1).and_then(|s| step_name(p, s)) {
                        self.r.at(intern(name));
                    }
                    let n = eval(size, &self.env(&values)).int();
                    windows.insert(i, self.r.push_limit(n)?);
                }
                Step::CloseWindow { open, exact } => {
                    if let Some(name) = p.steps.get(open + 1).and_then(|s| step_name(p, s)) {
                        self.r.at(intern(name));
                    }
                    let saved = windows.remove(open).unwrap_or(0);
                    self.r.pop_limit(saved, *exact)?;
                }
                _ => self.step(p, step, &mut values, start)?,
            }
            marks.insert(Mark::After(i), self.r.position_bits());
            for mi in checked_members(step) {
                for c in p.members[mi].enforced_checks() {
                    check(&c.cond, &c.message, &self.env(&values), |m| self.r.error(PbErrorKind::Constraint, m))?;
                }
            }
        }
        marks.insert(Mark::PacketEnd, self.r.position_bits());
        // Derived fields must hold what their expressions give.
        for &mi in &p.derived {
            let m = &p.members[mi];
            let (false, Some(e)) = (m.lenient, m.derived_expr()) else { continue };
            let r: &PbReader = self.r;
            let sum = |a, f, t, hf, ht| r.checksum(a, f, t, hf, ht);
            let env = Env { marks: Some(&marks), checksum: Some(&sum), ..Env::new(&values, &self.params) };
            let want = eval(e, &env).int();
            let got = match values[mi] {
                Value::Int(v) => v as i64,
                _ => 0,
            };
            if got != want {
                self.r.at(intern(&m.name));
                let msg = format!("`{}` is {} but the data gives {}", m.name, got, want);
                return Err(self.r.error(PbErrorKind::Mismatch, msg));
            }
        }
        self.r.leave();
        Ok(Struct { packet: p.name.clone(), fields: p.members.iter().map(|m| m.name.clone()).zip(values).collect() })
    }

    fn count(&mut self, e: &crate::ir::TExpr, values: &[Value], elem_bits: u64) -> Result<usize, PbError> {
        let n = eval(e, &self.env(values)).int();
        self.r.count(n, elem_bits)
    }

    fn step(&mut self, p: &Packet, step: &Step, values: &mut [Value], start: usize) -> Result<(), PbError> {
        match step {
            Step::Align { bytes } => {
                let skip = pad(self.r.position_bits() - start, *bytes as usize * 8);
                self.r.skip_bits(skip)
            }
            Step::Assert { index } => {
                self.r.at("");
                let a = &p.asserts[*index];
                check(&a.cond, &a.message, &self.env(values), |m| self.r.error(PbErrorKind::Constraint, m))
            }
            Step::Calc { member } => {
                let m = &p.members[*member];
                if let Some(e) = m.calc_expr() {
                    values[*member] = store(eval(e, &self.env(values)), &m.ty);
                }
                Ok(())
            }
            Step::Field { member, codec, array, ty } => {
                let name = member.map(|i| p.members[i].name.as_str()).unwrap_or("_");
                self.r.at(intern(name));
                match (member, codec) {
                    (Some(mi), Codec::Str(mode)) => {
                        let enc = p.members[*mi].encoding;
                        values[*mi] = self.string(values, mode, array.as_ref(), enc)?;
                    }
                    (None, codec) => {
                        let bits = codec.bits() as usize;
                        let skip = match array {
                            None => bits,
                            Some(Count::Expr(e)) => self.count(e, values, bits as u64)? * bits,
                            Some(Count::Remaining) => self.r.remaining_bits(),
                            // Rejected by the analysis for padding.
                            Some(Count::Until(_) | Count::Terminated { .. }) => 0,
                        };
                        self.r.skip_bits(skip)?;
                    }
                    (Some(mi), codec) => {
                        values[*mi] = match array {
                            None => self.elem(values, codec, ty)?,
                            Some(count) => self.array(values, ty, codec, count)?,
                        };
                    }
                }
                Ok(())
            }
            Step::Bitfield { name, container, container_width, parts } => {
                self.r.at(intern(name));
                self.bitfield(values, container, *container_width, parts)
            }
            Step::Switch { member, selector, arms } => {
                let m = &p.members[*member];
                self.r.at(intern(&m.name));
                let sel = eval(selector, &self.env(values)).int();
                let Some(arm) = arms.iter().find(|a| a.values.contains(&sel)).or(arms.iter().find(|a| a.default))
                else {
                    return Err(self.r.error(PbErrorKind::Invalid, format!("no arm of `{}` for {}", m.name, sel)));
                };
                let value = match (&arm.ty, &arm.codec, &arm.count) {
                    (None, ..) => None,
                    (Some(_), _, Some(count)) => {
                        let n = match count {
                            Count::Expr(e) => self.count(e, values, 8)?,
                            _ => self.r.remaining_bits() / 8,
                        };
                        Some(Box::new(Value::Bytes(self.r.read_bytes(n)?)))
                    }
                    (Some(ty), Some(codec), None) => Some(Box::new(self.elem(values, codec, ty)?)),
                    _ => None,
                };
                values[*member] = Value::Variant { arm: arm.name.clone(), value };
                Ok(())
            }
            Step::At { member, target, offset, root } => {
                self.r.at(intern(&p.members[*member].name));
                let off = eval(offset, &self.env(values)).int();
                let saved = self.r.jump(if *root { 0 } else { start }, off)?;
                values[*member] = self.elem(values, &Codec::Packet(target.clone()), &p.members[*member].ty)?;
                self.r.jump_back(saved);
                Ok(())
            }
            Step::OpenWindow { .. } | Step::CloseWindow { .. } => Ok(()),
        }
    }

    fn elem(&mut self, values: &[Value], codec: &Codec, ty: &ValueType) -> Result<Value, PbError> {
        let raw = match codec {
            Codec::Bytes { nbytes, endian } => self.r.read_uint(*nbytes, *endian == crate::ast::Endianness::Le)?,
            Codec::Bits { width } => self.r.read_bits(*width)?,
            Codec::Float { width: 32, endian } => {
                let raw = self.r.read_uint(4, *endian == crate::ast::Endianness::Le)?;
                return Ok(Value::Float(f32::from_bits(raw as u32) as f64));
            }
            Codec::Float { endian, .. } => {
                let raw = self.r.read_uint(8, *endian == crate::ast::Endianness::Le)?;
                return Ok(Value::Float(f64::from_bits(raw)));
            }
            Codec::Mac => return Ok(Value::Bytes(self.r.read_bytes(6)?)),
            Codec::Varint(kind) => self.r.read_varint(kind.id())?,
            Codec::Packet(target) => {
                let p = find(self.module, &target.name, self.r)?;
                let args = arguments(self.module, target, &self.env(values));
                return Ok(Value::Struct(self.packet(p, args)?));
            }
            Codec::Str(_) => unreachable!("strings are decoded by Decoder::string"),
        };
        Ok(int_value(raw, ty))
    }

    fn array(&mut self, values: &[Value], ty: &ValueType, codec: &Codec, count: &Count) -> Result<Value, PbError> {
        let ebits = codec.min_elem_bits();
        let n = match count {
            Count::Expr(e) => Some(self.count(e, values, ebits)?),
            Count::Terminated { term, optional } => return Ok(Value::Bytes(self.r.read_until(term, *optional)?)),
            Count::Until(cond) => {
                let mut items = Vec::new();
                while self.r.remaining_bits() > 0 {
                    self.r.at_index(items.len());
                    let item = self.elem(values, codec, ty)?;
                    let stop = eval(cond, &Env { last: Some(&item), ..self.env(values) }).bool();
                    items.push(item);
                    if stop {
                        break;
                    }
                }
                if ty.is_byte() {
                    let bytes = items.iter().map(|v| if let Value::Int(i) = v { *i as u8 } else { 0 }).collect();
                    return Ok(Value::Bytes(bytes));
                }
                return Ok(Value::List(items));
            }
            Count::Remaining => None,
        };
        if ty.is_byte() {
            let n = n.unwrap_or(self.r.remaining_bits() / 8);
            return Ok(Value::Bytes(self.r.read_bytes(n)?));
        }
        let mut items = Vec::new();
        match n {
            Some(n) => {
                for i in 0..n {
                    self.r.at_index(i);
                    items.push(self.elem(values, codec, ty)?);
                }
            }
            None => {
                while self.r.remaining_bits() > 0 {
                    self.r.at_index(items.len());
                    items.push(self.elem(values, codec, ty)?);
                }
            }
        }
        Ok(Value::List(items))
    }

    fn string(
        &mut self,
        values: &[Value],
        mode: &StrMode,
        array: Option<&Count>,
        enc: TextEncoding,
    ) -> Result<Value, PbError> {
        let raw = match (mode, array) {
            (StrMode::CString, _) => self.r.read_cstring()?,
            (StrMode::Terminated { term, optional }, _) => self.r.read_until(term, *optional)?,
            (StrMode::Prefixed { prefix, .. }, _) => {
                let n = match self.elem(values, prefix, &ValueType::Int { width: 64, signed: false })? {
                    Value::Int(v) => v as i64,
                    _ => 0,
                };
                let n = self.r.count(n, 8)?;
                self.r.read_bytes(n)?
            }
            (_, Some(Count::Expr(e))) => {
                let n = self.count(e, values, 8)?;
                self.r.read_bytes(n)?
            }
            _ => {
                let n = self.r.remaining_bits() / 8;
                self.r.read_bytes(n)?
            }
        };
        Ok(Value::Str(self.r.text(raw, enc.id(), *mode == StrMode::Padded)?))
    }

    fn bitfield(
        &mut self,
        values: &mut [Value],
        container: &Codec,
        container_width: u32,
        parts: &[BitPart],
    ) -> Result<(), PbError> {
        let c = match container {
            Codec::Bytes { nbytes, endian } => self.r.read_uint(*nbytes, *endian == crate::ast::Endianness::Le)?,
            _ => self.r.read_bits(container_width)?,
        };
        for part in parts {
            let bits = (c >> part.shift) & crate::generators::common::mask(part.width);
            values[part.member] =
                if part.signed { Value::Int(sext(bits, part.width) as i128) } else { Value::Int(bits as i128) };
        }
        Ok(())
    }
}

/// A raw integer read from the wire as a value of type `ty`.
fn int_value(raw: u64, ty: &ValueType) -> Value {
    match ty {
        ValueType::Int { width, signed: true } => Value::Int(sext(raw, *width) as i128),
        _ => Value::Int(raw as i128),
    }
}

/// The field a step reads, for error paths.
pub(super) fn step_name<'p>(p: &'p Packet, step: &'p Step) -> Option<&'p str> {
    match step {
        Step::Field { member: Some(m), .. } | Step::Switch { member: m, .. } => Some(&p.members[*m].name),
        Step::Field { member: None, .. } => Some("_"),
        Step::Bitfield { name, .. } => Some(name),
        _ => None,
    }
}
