//! `dissector` declarations: which packets get a Wireshark dissector.

use crate::ast::PacketExprList;
use crate::errors::Diagnostic;
use crate::ir::model::{Dissector, Packet};

/// Validate the file's `dissector` declarations against its packets.
pub(super) fn dissectors(list: &PacketExprList, packets: &[Packet], diags: &mut Vec<Diagnostic>) -> Vec<Dissector> {
    let mut out: Vec<Dissector> = Vec::new();
    for d in &list.dissectors {
        let Some(p) = packets.iter().find(|p| p.name == d.packet) else {
            diags.push(Diagnostic::new(format!("dissector for unknown packet `{}`", d.packet), d.span));
            continue;
        };
        if !p.params.is_empty() {
            diags.push(Diagnostic::new(
                format!("packet `{}` takes parameters, so it cannot have a dissector of its own", p.name),
                d.span,
            ));
        }
        let mut dis = Dissector::new(&p.name);
        for (key, value, span) in &d.strings {
            match key.as_str() {
                "name" => dis.name = value.clone(),
                "abbrev" => dis.abbrev = value.clone(),
                _ => diags.push(Diagnostic::new(format!("unknown dissector option `{}`", key), *span).with_note(
                    "options are name \"...\", abbrev \"...\", a table such as tcp.port 5190, and heuristic",
                )),
            }
        }
        dis.tables = d.tables.clone();
        dis.heuristic = d.heuristic;
        if let Err(msg) = Dissector::check_abbrev(&dis.abbrev) {
            diags.push(Diagnostic::new(msg, d.span));
        }
        if out.iter().any(|o| o.abbrev == dis.abbrev) {
            diags.push(Diagnostic::new(format!("two dissectors are called `{}`", dis.abbrev), d.span));
        }
        out.push(dis);
    }
    out
}
