//! Ada declares a subprogram's locals before its `begin`, so the emitters
//! collect them while writing the body into its own buffer.

use std::cell::RefCell;

use crate::generators::common::Out;

#[derive(Default)]
pub struct Locals {
    vars: RefCell<Vec<(String, String)>>,
}

impl Locals {
    /// Declare `name : ty` (once; Ada ignores case) and return the name.
    pub fn var(&self, name: impl Into<String>, ty: &str) -> String {
        let name = name.into();
        let mut vars = self.vars.borrow_mut();
        if !vars.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
            vars.push((name.clone(), ty.to_string()));
        }
        name
    }

    /// `<header> is`, the declarations, then `begin`, the body and
    /// `end <name>;`.
    pub fn routine(&self, out: &mut Out, header: &str, name: &str, body: Out) {
        out.line(format!("{} is", header));
        out.push();
        for (n, t) in self.vars.borrow().iter() {
            out.line(format!("{} : {};", n, t));
        }
        out.pop();
        out.line("begin");
        out.buf.push_str(&body.buf);
        out.line(format!("end {};", name));
    }
}

/// A buffer for a subprogram's body: one level in from its `begin`, which
/// is one level into the package body.
pub fn body() -> Out {
    let mut b = Out::new("   ");
    b.push();
    b.push();
    b
}
