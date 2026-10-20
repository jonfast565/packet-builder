//! Decoding by walking a packet's steps.

use super::eval::{Env, eval, store};
use super::rt::{PbError, PbErrorKind, PbReader};
use super::value::{Struct, Value};
use super::{check, checked_members, intern, pad, sext};
use std::collections::HashMap;

use crate::ir::{BitPart, Codec, Count, Mark, Module, Packet, Step, StrMode, ValueType};

/// Decode packet `name` from the start of `data`; trailing bytes are ignored.
pub fn decode(module: &Module, name: &str, data: &[u8]) -> Result<Value, PbError> {
    let mut r = PbReader::new(data);
    decode_from(module, name, &mut r)
}

/// Decode packet `name` at the reader's position.
pub fn decode_from(module: &Module, name: &str, r: &mut PbReader) -> Result<Value, PbError> {
    let p = find(module, name, r)?;
    Ok(Value::Struct(Decoder { module, r }.packet(p)?))
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
}

impl Decoder<'_, '_, '_> {
    fn packet(&mut self, p: &Packet) -> Result<Struct, PbError> {
        self.r.enter(intern(&p.name))?;
        let mut values: Vec<Value> = p.members.iter().map(|m| Value::default_for(self.module, m)).collect();
        let start = self.r.position_bits();
        let mut marks = HashMap::from([(Mark::PacketStart, start)]);
        for (i, step) in p.steps.iter().enumerate() {
            marks.insert(Mark::Before(i), self.r.position_bits());
            self.step(p, step, &mut values, start)?;
            marks.insert(Mark::After(i), self.r.position_bits());
            for mi in checked_members(step) {
                for c in p.members[mi].enforced_checks() {
                    check(&c.cond, &c.message, &values, |m| self.r.error(PbErrorKind::Constraint, m))?;
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
            let want = eval(e, &Env { values: &values, marks: Some(&marks), checksum: Some(&sum) }).int();
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
        let n = eval(e, &Env::new(values)).int();
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
                check(&a.cond, &a.message, values, |m| self.r.error(PbErrorKind::Constraint, m))
            }
            Step::Calc { member } => {
                let m = &p.members[*member];
                if let Some(e) = m.calc_expr() {
                    values[*member] = store(eval(e, &Env::new(values)), &m.ty);
                }
                Ok(())
            }
            Step::Field { member, codec, array, ty } => {
                let name = member.map(|i| p.members[i].name.as_str()).unwrap_or("_");
                self.r.at(intern(name));
                match (member, codec) {
                    (Some(mi), Codec::Str(mode)) => {
                        values[*mi] = self.string(values, mode, array.as_ref())?;
                    }
                    (None, codec) => {
                        let bits = codec.bits() as usize;
                        let skip = match array {
                            None => bits,
                            Some(Count::Expr(e)) => self.count(e, values, bits as u64)? * bits,
                            Some(Count::Remaining) => self.r.remaining_bits(),
                        };
                        self.r.skip_bits(skip)?;
                    }
                    (Some(mi), codec) => {
                        values[*mi] = match array {
                            None => self.elem(codec, ty)?,
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
        }
    }

    fn elem(&mut self, codec: &Codec, ty: &ValueType) -> Result<Value, PbError> {
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
            Codec::Packet(n) => {
                let p = find(self.module, n, self.r)?;
                return Ok(Value::Struct(self.packet(p)?));
            }
            Codec::Str(_) => unreachable!("strings are decoded by Decoder::string"),
        };
        Ok(int_value(raw, ty))
    }

    fn array(&mut self, values: &[Value], ty: &ValueType, codec: &Codec, count: &Count) -> Result<Value, PbError> {
        let ebits = codec.min_elem_bits();
        let n = match count {
            Count::Expr(e) => Some(self.count(e, values, ebits)?),
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
                    items.push(self.elem(codec, ty)?);
                }
            }
            None => {
                while self.r.remaining_bits() > 0 {
                    self.r.at_index(items.len());
                    items.push(self.elem(codec, ty)?);
                }
            }
        }
        Ok(Value::List(items))
    }

    fn string(&mut self, values: &[Value], mode: &StrMode, array: Option<&Count>) -> Result<Value, PbError> {
        let raw = match (mode, array) {
            (StrMode::CString, _) => self.r.read_cstring()?,
            (StrMode::Prefixed { prefix, .. }, _) => {
                let n = match self.elem(prefix, &ValueType::Int { width: 64, signed: false })? {
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
        let raw = if *mode == StrMode::Padded {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            raw[..end].to_vec()
        } else {
            raw
        };
        Ok(Value::Str(self.r.utf8(raw)?))
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
