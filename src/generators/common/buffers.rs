//! Which packets and unions hold byte buffers or strings, directly or in
//! what they contain: in zero-copy Rust they borrow the input (`<'a>`).

use std::collections::HashSet;

use crate::ir::{Member, Module, ValueType};

/// A member holding bytes or text itself.
pub fn is_buffer(m: &Member) -> bool {
    m.ty == ValueType::Str || (m.array.is_some() && m.ty.is_byte())
}

/// Names of the packets and unions that hold buffers, transitively.
pub fn holding_buffers(module: &Module) -> HashSet<String> {
    let mut set = HashSet::new();
    loop {
        let before = set.len();
        for p in &module.packets {
            let holds = p.members.iter().any(|m| {
                is_buffer(m) || matches!(&m.ty, ValueType::Packet(n) | ValueType::Union(n) if set.contains(n))
            });
            if holds {
                set.insert(p.name.clone());
            }
        }
        for u in &module.unions {
            let holds =
                u.arms.iter().any(|a| a.is_bytes() || matches!(&a.ty, Some(ValueType::Packet(n)) if set.contains(n)));
            if holds {
                set.insert(u.name.clone());
            }
        }
        if set.len() == before {
            return set;
        }
    }
}
