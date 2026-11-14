//! A reference interpreter: decodes and encodes packets by walking a
//! [`Module`]'s steps directly, with the same runtime ([`rt`], the Rust
//! backend's runtime) and the same expression semantics as generated code.
//! It is the executable specification the generated codecs are tested
//! against, and it powers the `decode` command.

mod decode;
mod encode;
mod eval;
mod frame;
mod show;
mod value;

pub use decode::{decode, decode_args, decode_from, decode_from_args, decode_version};
pub use encode::{encode, encode_args, encode_version};
pub use frame::frame_length;
pub use rt::{PbError as Error, PbErrorKind as ErrorKind, PbFetch as Fetch, PbReader as Reader, PbSource as Source};
pub use show::render;
pub use value::{Struct, Value};

/// The Rust backend's runtime, compiled into the crate.
#[allow(dead_code, clippy::all)]
mod rt {
    include!("../../../runtime/rust.rs");
}

use std::collections::HashSet;
use std::sync::Mutex;

/// Field and packet names as `&'static str`, which the runtime's error trace
/// stores. Each distinct name is allocated once.
fn intern(name: &str) -> &'static str {
    static NAMES: Mutex<Option<HashSet<&'static str>>> = Mutex::new(None);
    let mut guard = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    if let Some(s) = set.get(name) {
        return s;
    }
    let s: &'static str = Box::leak(name.to_string().into_boxed_str());
    set.insert(s);
    s
}

/// The versions packet `name` is coded in: (min, latest); (1, 1) without
/// versions (or for an unknown packet, which coding then reports).
fn versions(module: &crate::ir::Module, name: &str) -> (u32, u32) {
    module.packets.iter().find(|p| p.name == name).map_or((1, 1), |p| p.version_bounds())
}

/// The index of the `CloseGate` that ends the gate opened at step `open`.
fn gate_end(p: &crate::ir::Packet, open: usize) -> usize {
    p.steps
        .iter()
        .enumerate()
        .skip(open)
        .find(|(_, s)| matches!(s, crate::ir::Step::CloseGate { open: o } if *o == open))
        .map(|(i, _)| i)
        .unwrap_or(p.steps.len())
}

/// Padding after `offset` bits to reach a multiple of `unit` bits.
fn pad(offset: usize, unit: usize) -> usize {
    (unit - offset % unit) % unit
}

fn sext(v: u64, width: u32) -> i64 {
    if width < 64 && (v >> (width - 1)) & 1 == 1 { (v | (u64::MAX << width)) as i64 } else { v as i64 }
}

/// Members whose enforced checks apply to a step (the field it reads or
/// writes, or a bitfield's parts).
fn checked_members(step: &crate::ir::Step) -> Vec<usize> {
    use crate::ir::Step;
    match step {
        Step::Field { member: Some(mi), array: None, .. } => vec![*mi],
        Step::Bitfield { parts, .. } => parts.iter().map(|b| b.member).collect(),
        _ => Vec::new(),
    }
}

/// Fail with a `constraint` error unless `cond` holds.
fn check(
    cond: &crate::ir::TExpr,
    message: &str,
    env: &eval::Env,
    fail: impl FnOnce(String) -> Error,
) -> Result<(), Error> {
    if eval::eval(cond, env).bool() { Ok(()) } else { Err(fail(message.to_string())) }
}

/// The arguments of a nested packet, evaluated in the containing packet and
/// wrapped to the parameter types.
fn arguments(module: &crate::ir::Module, target: &crate::ir::PacketRef, env: &eval::Env) -> Vec<i64> {
    let params = module.packets.iter().find(|p| p.name == target.name).map(|p| p.params.as_slice()).unwrap_or(&[]);
    target
        .args
        .iter()
        .zip(params)
        .map(|(a, prm)| match eval::store(eval::eval(a, env), &prm.ty) {
            Value::Int(v) => v as i64,
            _ => 0,
        })
        .collect()
}
