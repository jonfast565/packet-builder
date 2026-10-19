//! Builds the validated [`Module`] from the parse tree.
//!
//! - [`analyze`] (this file): packet names and dependency order.
//! - `packet`: per-packet passes ([`PacketBuilder`](packet::PacketBuilder)).
//! - `context`: the member table and diagnostics shared by those passes.
//! - `typecheck`, `codec`: expression and wire-format resolution.
//! - `cursor`: what is known about the bit offset while laying out fields.
//! - `types`: facts about source type names.

mod codec;
mod context;
mod cursor;
mod packet;
mod typecheck;
mod types;

use std::collections::HashMap;

use super::model::{Module, Packet};
use crate::ast::{PacketExprList, PacketItem, TypeNode};
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
    let order = match packet_order(list, &by_name) {
        Ok(o) => o,
        Err(d) => {
            diags.extend(d);
            return Err(diags);
        }
    };

    let mut done = HashMap::<String, Packet>::new();
    for idx in order {
        match packet::PacketBuilder::new(&list.packets[idx], &done).build() {
            Ok(packet) => {
                done.insert(packet.name.clone(), packet);
            }
            Err(d) => diags.extend(d),
        }
    }

    if !diags.is_empty() {
        return Err(diags);
    }

    let packets = list.packets.iter().map(|p| done.remove(&p.name).expect("analyzed")).collect();
    Ok(Module { packets })
}

fn packet_order(list: &PacketExprList, by_name: &HashMap<String, usize>) -> Result<Vec<usize>, Vec<Diagnostic>> {
    let mut diags = Vec::new();
    let mut state = vec![0u8; list.packets.len()]; // 0 = new, 1 = visiting, 2 = done
    let mut order = Vec::new();

    fn visit(
        i: usize,
        list: &PacketExprList,
        by_name: &HashMap<String, usize>,
        state: &mut Vec<u8>,
        order: &mut Vec<usize>,
        diags: &mut Vec<Diagnostic>,
    ) {
        if state[i] == 2 {
            return;
        }
        if state[i] == 1 {
            diags.push(Diagnostic::new(
                format!("packet `{}` contains itself", list.packets[i].name),
                list.packets[i].span,
            ));
            return;
        }
        state[i] = 1;
        for item in &list.packets[i].items {
            if let PacketItem::Field(f) = item
                && let TypeNode::Packet(name) = &f.expr
            {
                match by_name.get(name) {
                        Some(j) => visit(*j, list, by_name, state, order, diags),
                        None => diags.push(Diagnostic::new(format!("unknown type `{}`", name), f.span).with_note(
                            "built-in types are uint8..uint64, int8..int64, uN/iN, float32, float64, macaddress, datetime, bytes",
                        )),
                    }
            }
        }
        state[i] = 2;
        order.push(i);
    }

    for i in 0..list.packets.len() {
        visit(i, list, by_name, &mut state, &mut order, &mut diags);
    }
    if diags.is_empty() { Ok(order) } else { Err(diags) }
}
