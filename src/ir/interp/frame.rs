//! Evaluating a [`FrameLength`] over the first bytes of a stream.

use super::eval::{Env, eval, store};
use super::rt::{PbError, PbErrorKind, PbReader};
use super::{Value, sext};
use crate::ir::frame::FrameLength;
use crate::ir::{Codec, Module, Packet};

/// The size in bytes of the packet `p` starting at `data`, from its header;
/// an `incomplete` error while `data` is shorter than the header.
pub fn frame_length(_module: &Module, p: &Packet, f: &FrameLength, data: &[u8]) -> Result<i64, PbError> {
    let mut values: Vec<Value> = vec![Value::Int(0); p.members.len()];
    let mut r = PbReader::new(data);
    if (data.len() as u64) < f.header_bytes {
        let mut e = r.error(PbErrorKind::Incomplete, format!("the header needs {} bytes", f.header_bytes));
        e.needed_bits = ((f.header_bytes - data.len() as u64) * 8) as usize;
        return Err(e);
    }
    for (fi, h) in f.fields.iter().enumerate() {
        if h.when.as_ref().is_some_and(|c| !eval(c, &Env::new(&values, &[])).bool()) {
            continue;
        }
        r.jump(0, 0)?;
        r.skip_bits(h.offset_bits as usize)?;
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => r.read_uint(*nbytes, *endian == crate::ast::Endianness::Le)?,
            _ => r.read_bits(h.container_bits)?,
        };
        let bits = (raw >> h.shift) & crate::generators::common::mask(h.bits);
        let v = if h.signed { sext(bits, h.bits) as i128 } else { bits as i128 };
        values[h.member] = Value::Int(v);
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            let need = eval(need, &Env::new(&values, &[])).int().max(0) as u64;
            if (data.len() as u64) < need {
                let mut e = r.error(PbErrorKind::Incomplete, format!("the header needs {} bytes", need));
                e.needed_bits = ((need - data.len() as u64) * 8) as usize;
                return Err(e);
            }
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            values[c] = store(eval(e, &Env::new(&values, &[])), &m.ty);
        }
    }
    Ok(eval(&f.total, &Env::new(&values, &[])).int())
}
