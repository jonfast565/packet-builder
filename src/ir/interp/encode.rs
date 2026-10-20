//! Encoding by walking a packet's steps.

use super::eval::{Env, eval, store};
use super::rt::{PbError, PbErrorKind, PbWriter};
use super::value::{Struct, Value};
use super::{intern, pad};
use crate::ast::Endianness;
use crate::ir::{BitPart, Codec, Count, Module, Packet, Step, StrMode, ValueType};

/// Encode `value`, a packet named `name`. Members missing from the value
/// count as zero.
pub fn encode(module: &Module, name: &str, value: &Value) -> Result<Vec<u8>, PbError> {
    let mut w = PbWriter::new();
    let p = find(module, name, &w)?;
    let s = match value {
        Value::Struct(s) => s.clone(),
        _ => return Err(w.error(PbErrorKind::Invalid, format!("a value of packet `{}` must be a struct", name))),
    };
    Encoder { module }.packet(p, &s, &mut w)?;
    Ok(w.finish())
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
}

impl Encoder<'_> {
    fn packet(&self, p: &Packet, s: &Struct, w: &mut PbWriter) -> Result<(), PbError> {
        w.enter(intern(&p.name))?;
        let mut values: Vec<Value> = p
            .members
            .iter()
            .map(|m| s.get(&m.name).cloned().unwrap_or_else(|| Value::default_for(self.module, m)))
            .collect();
        // Calculated members that lengths depend on are recomputed, as in
        // generated encoders.
        for (m, e) in p.encode_calc_members() {
            let idx = p.members.iter().position(|x| x.name == m.name).expect("member");
            values[idx] = store(eval(e, &Env { values: &values }), &m.ty);
        }
        let start = w.position_bits();
        for step in &p.steps {
            self.step(p, step, &values, start, w)?;
        }
        w.leave();
        Ok(())
    }

    fn expr(&self, values: &[Value], e: &crate::ir::TExpr) -> i64 {
        eval(e, &Env { values }).int()
    }

    fn step(&self, p: &Packet, step: &Step, values: &[Value], start: usize, w: &mut PbWriter) -> Result<(), PbError> {
        match step {
            Step::Align { bytes } => {
                w.write_zero_bits(pad(w.position_bits() - start, *bytes as usize * 8));
                Ok(())
            }
            Step::Calc { .. } => Ok(()),
            Step::Field { member, codec, array, ty } => {
                let name = member.map(|i| p.members[i].name.as_str()).unwrap_or("_");
                w.at(intern(name));
                match (member, codec) {
                    (Some(mi), Codec::Str(mode)) => self.string(values, &values[*mi], mode, array.as_ref(), w),
                    (None, codec) => {
                        let bits = codec.bits() as usize;
                        match array {
                            None => w.write_zero_bits(bits),
                            Some(Count::Expr(e)) => w.write_zero_bits(self.expr(values, e).max(0) as usize * bits),
                            Some(Count::Remaining) => {}
                        }
                        Ok(())
                    }
                    (Some(mi), codec) => match array {
                        None => self.elem(codec, ty, &values[*mi], w),
                        Some(count) => self.array(values, &values[*mi], ty, codec, count, w),
                    },
                }
            }
            Step::Bitfield { name, container, container_width, parts } => {
                w.at(intern(name));
                self.bitfield(values, container, *container_width, parts, w)
            }
        }
    }

    fn elem(&self, codec: &Codec, ty: &ValueType, v: &Value, w: &mut PbWriter) -> Result<(), PbError> {
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
            Codec::Mac => match v {
                Value::Bytes(b) if b.len() == 6 => w.write_bytes(b),
                _ => return Err(w.error(PbErrorKind::Range, "a MAC address needs 6 bytes".into())),
            },
            Codec::Packet(n) => {
                let p = find(self.module, n, w)?;
                let s = match v {
                    Value::Struct(s) => s.clone(),
                    _ => Struct::default_for(self.module, p),
                };
                self.packet(p, &s, w)?;
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
        for (i, item) in items.iter().enumerate() {
            w.at_index(i);
            self.elem(codec, ty, item, w)?;
        }
        Ok(())
    }

    fn string(
        &self,
        values: &[Value],
        v: &Value,
        mode: &StrMode,
        array: Option<&Count>,
        w: &mut PbWriter,
    ) -> Result<(), PbError> {
        let text = match v {
            Value::Str(s) => s.clone(),
            _ => String::new(),
        };
        let b = text.as_bytes();
        match (mode, array) {
            (StrMode::CString, _) => {
                w.check_no_nul(b)?;
                w.write_bytes(b);
                w.write_bytes(&[0]);
            }
            (StrMode::Prefixed { prefix, width }, _) => {
                w.check_u(b.len() as u64, *width)?;
                self.elem(prefix, &ValueType::Int { width: 64, signed: false }, &Value::Int(b.len() as i128), w)?;
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
