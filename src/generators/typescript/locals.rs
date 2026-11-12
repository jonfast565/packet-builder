//! Locals that outlive the block they are set in (marks, windows, encode-time
//! values): the emitters collect them while writing a method's body, and the
//! method declares them all at its top.

use std::cell::RefCell;

use crate::generators::common::Out;

#[derive(Default)]
pub struct Locals {
    vars: RefCell<Vec<(String, String, String)>>,
}

impl Locals {
    /// Declare `name: ty = init` at the top of the method (once).
    pub fn declare(&self, name: &str, ty: &str, init: &str) {
        let mut vars = self.vars.borrow_mut();
        if !vars.iter().any(|(n, ..)| n == name) {
            vars.push((name.into(), ty.into(), init.into()));
        }
    }

    fn emit(&self, out: &mut Out) {
        for (name, ty, init) in self.vars.borrow().iter() {
            out.line(format!("let {}: {} = {};", name, ty, init));
        }
    }
}

/// Write the body `steps` produces at `out`'s level + `depth`, preceded by
/// the locals it declared.
pub fn emit_body(out: &mut Out, depth: usize, locals: &Locals, steps: impl FnOnce(&mut Out)) {
    let mut body = Out::new("  ");
    for _ in 0..depth {
        body.push();
    }
    steps(&mut body);
    let mut head = Out::new("  ");
    for _ in 0..depth {
        head.push();
    }
    locals.emit(&mut head);
    out.buf.push_str(&head.buf);
    out.buf.push_str(&body.buf);
}
