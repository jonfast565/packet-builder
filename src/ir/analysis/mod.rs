//! Builds the validated [`Module`] from the parse tree.
//!
//! - [`analyze`] (this file): packet names and dependency order.
//! - `packet`: per-packet passes ([`PacketBuilder`](packet::PacketBuilder)).
//! - `consts`: named constants and categories, and `: Category` tags.
//! - `bitfield`: bitfield containers and their sub-fields.
//! - `checks`: `== value`, `in lo..hi`, `strict` and `lenient` on fields.
//! - `derive`: derived fields, their marks and the encode order.
//! - `union`: tagged unions (`switch`) and windows (`size n`).
//! - `repeat`: `until` and `term`, and string encodings.
//! - `params`: packet parameters, arguments, `at` fields and the order
//!   packets are analyzed in (recursion through arrays and `at`).
//! - `context`: the member table and diagnostics shared by those passes.
//! - `typecheck`, `codec`: expression and wire-format resolution.
//! - `cursor`: what is known about the bit offset while laying out fields.
//! - `types`: facts about source type names.

mod bitfield;
mod checks;
mod codec;
mod consts;
mod context;
mod cursor;
mod derive;
mod packet;
mod params;
mod repeat;
mod typecheck;
mod types;
mod union;

use std::collections::HashMap;

use super::model::{Module, Packet, Step, Union, ValueType};
use crate::ast::PacketExprList;
use crate::errors::Diagnostic;

/// Type names a packet may not take.
const BUILTIN: &[&str] = &[
    "int8",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "int64",
    "uint64",
    "float32",
    "float64",
    "macaddress",
    "datetime",
    "bytes",
    "char",
    "uchar",
    "byte",
    "short",
    "ushort",
    "int",
    "uint",
    "halfword",
    "word",
    "dword",
    "doubleword",
    "qword",
    "quadword",
    "string",
    "cstring",
];

pub fn analyze(list: &PacketExprList) -> Result<Module, Vec<Diagnostic>> {
    let mut diags = Vec::new();

    // Packet names
    let mut by_name = HashMap::<String, usize>::new();
    for (i, p) in list.packets.iter().enumerate() {
        let looks_like_bits = p.name.len() > 1
            && (p.name.starts_with('u') || p.name.starts_with('i'))
            && p.name[1..].chars().all(|c| c.is_ascii_digit());
        if BUILTIN.contains(&p.name.as_str()) || looks_like_bits {
            diags.push(Diagnostic::new(format!("packet name `{}` is a built-in type name", p.name), p.span));
        }
        if by_name.insert(p.name.clone(), i).is_some() {
            diags.push(Diagnostic::new(format!("packet `{}` is declared more than once", p.name), p.span));
        }
    }

    // Dependency order between packets (nested packets first), rejecting cycles.
    let order = match params::packet_order(list, &by_name) {
        Ok(o) => o,
        Err(d) => {
            diags.extend(d);
            return Err(diags);
        }
    };

    let sigs = params::signatures(list, &mut diags);
    let consts = consts::ConstTable::build(list, &mut diags);
    let mut done = HashMap::<String, Packet>::new();
    for idx in order {
        match packet::PacketBuilder::new(&list.packets[idx], &done, &sigs, &consts).build() {
            Ok(packet) => {
                done.insert(packet.name.clone(), packet);
            }
            Err(d) => diags.extend(d),
        }
    }

    if !diags.is_empty() {
        return Err(diags);
    }

    let packets: Vec<Packet> = list.packets.iter().map(|p| done.remove(&p.name).expect("analyzed")).collect();
    let mut unions = Vec::new();
    for p in &packets {
        for s in &p.steps {
            if let Step::Switch { member, arms, .. } = s
                && let ValueType::Union(name) = &p.members[*member].ty
            {
                unions.push(Union { name: name.clone(), arms: arms.clone() });
            }
        }
    }
    let taken: Vec<&str> =
        packets.iter().map(|p| p.name.as_str()).chain(consts.categories.iter().map(|c| c.name.as_str())).collect();
    for (i, p) in list.packets.iter().enumerate() {
        for u in unions.iter().filter(|u| u.name.starts_with(&p.name)) {
            if taken.contains(&u.name.as_str()) {
                diags.push(Diagnostic::new(
                    format!("the union type `{}` has the same name as a packet or category", u.name),
                    list.packets[i].span,
                ));
            }
        }
    }
    if !diags.is_empty() {
        return Err(diags);
    }
    Ok(Module { packets, constants: consts.constants, categories: consts.categories, unions })
}
