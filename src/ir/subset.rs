//! A module for some of its protocol versions only (`generate --versions
//! 2..3`): what exists in no other version is dropped, so generated code
//! stays small, and the runtimes reject any version outside the range.

use super::expr::{CmpOp, LogicOp, Mark, TExpr};
use super::model::{Module, Packet, Step, Versions};

impl Module {
    /// Keep versions `min..=latest` only.
    pub fn restrict_versions(&mut self, min: u32, latest: u32) -> Result<(), String> {
        let Some(all) = self.versions else {
            return Err("--versions needs a file with versions (`version N`)".into());
        };
        if min < all.min || latest > all.latest || min > latest {
            return Err(format!("versions {}..{} are not within {}..{}", min, latest, all.min, all.latest));
        }
        let versions = Some(Versions { min, latest });
        self.versions = versions;
        for p in &mut self.packets {
            restrict(p, min, latest);
            p.versions = versions;
        }
        Ok(())
    }
}

fn restrict(p: &mut Packet, min: u32, latest: u32) {
    let mut steps = Vec::with_capacity(p.steps.len());
    // Old step index -> new one, for the steps kept.
    let mut map = vec![usize::MAX; p.steps.len()];
    // An open gate: dropped with its steps, unwrapped, or kept.
    let mut gate: Option<(bool, bool)> = None;
    for (i, step) in p.steps.iter().enumerate() {
        match step {
            Step::OpenGate { from, to, .. } => {
                let never = *to < min || *from > latest;
                let always = *from <= min && *to >= latest;
                gate = Some((never, always));
                if !never && !always {
                    map[i] = steps.len();
                    steps.push(Step::OpenGate { from: *from, to: *to, cond: test(*from, *to, min, latest) });
                }
            }
            Step::CloseGate { open } => {
                if let Some((false, false)) = gate {
                    map[i] = steps.len();
                    steps.push(Step::CloseGate { open: map[*open] });
                }
                gate = None;
            }
            _ if matches!(gate, Some((true, _))) => {}
            Step::CloseWindow { open, exact } => {
                map[i] = steps.len();
                steps.push(Step::CloseWindow { open: map[*open], exact: *exact });
            }
            _ => {
                map[i] = steps.len();
                steps.push(step.clone());
            }
        }
    }
    // Recorded positions are never inside gates (analysis rejects that), so
    // every step they name is kept.
    let remap = |m: &mut Mark| match m {
        Mark::Before(i) | Mark::After(i) => *i = map[*i],
        Mark::PacketStart | Mark::PacketEnd => {}
    };
    for m in &mut p.members {
        if let super::model::MemberKind::Derived(e) = &mut m.kind {
            e.visit_mut(&mut |x| {
                if let TExpr::Size { from, to } | TExpr::Checksum { from, to, .. } = x {
                    remap(from);
                    remap(to);
                }
                if let TExpr::Checksum { hole: Some((a, b)), .. } = x {
                    remap(a);
                    remap(b);
                }
            });
        }
    }
    p.steps = steps;
}

/// The test for versions `from..=to` among `min..=latest`, without the
/// comparisons every one of them passes.
fn test(from: u32, to: u32, min: u32, latest: u32) -> TExpr {
    let cmp = |op, v: u32| TExpr::Cmp { op, a: Box::new(TExpr::Version), b: Box::new(TExpr::IntLit(v as i64)) };
    let lo = (from > min).then(|| cmp(CmpOp::Gte, from));
    let hi = (to < latest).then(|| cmp(CmpOp::Lte, to));
    match (lo, hi) {
        (Some(a), Some(b)) => TExpr::Logic { op: LogicOp::And, a: Box::new(a), b: Box::new(b) },
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => TExpr::Cmp { op: CmpOp::Eq, a: Box::new(TExpr::IntLit(0)), b: Box::new(TExpr::IntLit(0)) },
    }
}
