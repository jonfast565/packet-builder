//! Fortran declares every local before the first statement, so the
//! emitters collect them while writing the body into its own buffer.
//! Locals are never initialized in their declaration (that would make them
//! `save`d, shared between recursive calls).

use std::cell::RefCell;

use crate::generators::common::Out;

#[derive(Default)]
pub struct Locals {
    vars: RefCell<Vec<(String, String)>>,
}

impl Locals {
    /// Declare `name` (once) with type `ty` (attributes included) and
    /// return it; `dims` (`(:)`) follows the name.
    pub fn var(&self, name: impl Into<String>, ty: &str) -> String {
        self.decl(name, ty, "")
    }

    /// An allocatable array local.
    pub fn array(&self, name: impl Into<String>, elem: &str) -> String {
        self.decl(name, &format!("{}, allocatable", elem), "(:)")
    }

    fn decl(&self, name: impl Into<String>, ty: &str, dims: &str) -> String {
        let name = name.into();
        let mut vars = self.vars.borrow_mut();
        if !vars.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
            vars.push((name.clone(), format!("{} :: {}{}", ty, name, dims)));
        }
        name
    }

    /// The declarations, then the body.
    pub fn routine(&self, out: &mut Out, body: Out) {
        let vars = self.vars.borrow();
        out.push();
        for (_, d) in vars.iter() {
            out.line(d);
        }
        out.pop();
        out.buf.push_str(&body.buf);
    }
}

/// A buffer for a procedure's body, one level in.
pub fn body() -> Out {
    let mut b = Out::new("  ");
    b.push();
    b.push();
    b
}
