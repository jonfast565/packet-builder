//! COBOL declares every variable in the DATA DIVISION, before the
//! procedure, so the emitters collect a program's locals while writing its
//! body. Packet programs are RECURSIVE (packets can contain themselves
//! through arrays), so their locals live in LOCAL-STORAGE: one copy per
//! invocation.

use std::cell::{Cell, RefCell};

use crate::generators::common::Out;

/// `BINARY-DOUBLE SIGNED`: what integer locals are.
pub const INT: &str = "BINARY-DOUBLE SIGNED";
/// `FLOAT-LONG`: what float locals are.
pub const FLOAT: &str = "FLOAT-LONG";

#[derive(Default)]
pub struct Locals {
    vars: RefCell<Vec<(String, String)>>,
    temps: Cell<usize>,
}

impl Locals {
    /// Declare `name` (once) with `usage` and return it.
    pub fn var(&self, name: impl Into<String>, usage: &str) -> String {
        let name = name.into();
        let mut vars = self.vars.borrow_mut();
        if !vars.iter().any(|(n, _)| *n == name) {
            vars.push((name.clone(), usage.to_string()));
        }
        name
    }

    /// A fresh integer temporary.
    pub fn int(&self) -> String {
        let n = self.temps.get();
        self.temps.set(n + 1);
        self.var(format!("PL-T{}", n), INT)
    }

    /// A fresh float temporary.
    pub fn float(&self) -> String {
        let n = self.temps.get();
        self.temps.set(n + 1);
        self.var(format!("PL-F{}", n), FLOAT)
    }

    /// The `LOCAL-STORAGE SECTION` with every local.
    pub fn section(&self, out: &mut Out, title: &str) {
        let vars = self.vars.borrow();
        out.line(title);
        for (n, u) in vars.iter() {
            out.line(format!("01 {} {}.", n, u));
        }
    }
}

/// A buffer for a procedure body, one level in.
pub fn body() -> Out {
    let mut b = Out::new("    ");
    b.push();
    b
}
