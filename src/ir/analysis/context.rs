//! The member table and diagnostics shared by the analysis passes of one packet.

use std::collections::{HashMap, HashSet};

use crate::errors::Diagnostic;
use crate::ir::expr::TExpr;
use crate::ir::model::{Member, MemberKind, Packet, Step, ValueType};
use crate::models::parsing_models::{PacketExpr, Span};

pub(super) struct Ctx<'a> {
    pub packet: &'a PacketExpr,
    pub done: &'a HashMap<String, Packet>,
    pub members: Vec<Member>,
    pub names: HashMap<String, usize>,
    pub diags: Vec<Diagnostic>,
}

impl<'a> Ctx<'a> {
    pub fn new(packet: &'a PacketExpr, done: &'a HashMap<String, Packet>) -> Self {
        Ctx { packet, done, members: Vec::new(), names: HashMap::new(), diags: Vec::new() }
    }

    pub fn declare(&mut self, name: &str, ty: ValueType, kind: MemberKind, span: Span) {
        if name.starts_with("pb_") || name.starts_with("pbc_") || name.starts_with("_pb") {
            self.diags.push(Diagnostic::new(
                format!("field name `{}` is reserved (prefixes pb_, pbc_ and _pb are used by generated code)", name),
                span,
            ));
        }
        if self.names.contains_key(name) {
            self.diags.push(Diagnostic::new(
                format!("`{}` is declared more than once in packet `{}`", name, self.packet.name),
                span,
            ));
            return;
        }
        self.names.insert(name.to_string(), self.members.len());
        self.members.push(Member { name: name.to_string(), ty, array: None, kind });
    }

    /// Add calculated fields to the decode steps once their inputs are known.
    pub fn schedule_calcs(&self, steps: &mut Vec<Step>, available: &HashSet<usize>, scheduled: &mut HashSet<usize>) {
        loop {
            let mut progressed = false;
            for (idx, m) in self.members.iter().enumerate() {
                if scheduled.contains(&idx) {
                    continue;
                }
                if let MemberKind::Calculated(e) = &m.kind {
                    let mut deps = Vec::new();
                    e.deps(&mut deps);
                    if deps.iter().all(|d| *d != idx && (available.contains(d) || scheduled.contains(d))) {
                        scheduled.insert(idx);
                        steps.push(Step::Calc { member: idx });
                        progressed = true;
                    }
                }
            }
            if !progressed {
                break;
            }
        }
    }

    pub fn require_available(
        &mut self,
        e: &TExpr,
        available: &HashSet<usize>,
        scheduled: &HashSet<usize>,
        span: Span,
        field: &str,
    ) {
        let mut deps = Vec::new();
        e.deps(&mut deps);
        for d in deps {
            if !available.contains(&d) && !scheduled.contains(&d) {
                let name = self.members[d].name.clone();
                self.diags.push(Diagnostic::new(
                    format!("the length of `{}` uses `{}`, which is not known yet at that point", field, name),
                    span,
                ).with_note("lengths may only use fields declared before them (or calculated fields that depend only on those)"));
            }
        }
    }
}
