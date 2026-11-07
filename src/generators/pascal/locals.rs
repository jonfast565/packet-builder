//! Pascal declares every local in a `var` block before the body, so the
//! emitters collect them while writing the body into its own buffer.

use std::cell::RefCell;

use crate::generators::common::Out;

#[derive(Default)]
pub struct Locals {
    vars: RefCell<Vec<(String, String)>>,
}

impl Locals {
    /// Declare `name` (once) and return it.
    pub fn var(&self, name: impl Into<String>, ty: &str) -> String {
        let name = name.into();
        let mut vars = self.vars.borrow_mut();
        if !vars.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
            vars.push((name.clone(), ty.to_string()));
        }
        name
    }

    /// The `var` block, then `begin`, the body and `end;`.
    pub fn routine(&self, out: &mut Out, body: Out) {
        let vars = self.vars.borrow();
        if !vars.is_empty() {
            out.open("var");
            for (n, t) in vars.iter() {
                out.line(format!("{}: {};", n, t));
            }
            out.pop();
        }
        out.open("begin");
        out.buf.push_str(&body.buf);
        out.close("end;");
    }
}

/// A buffer for a routine's body, one level in from `begin`.
pub fn body() -> Out {
    let mut b = Out::new("  ");
    b.push();
    b
}
