//! Pieces shared by every backend.
//!
//! - [`options`] — [`GenOptions`].
//! - [`consts`] — the [`ConstEmitter`] template for named constants.
//! - [`out`] — the indented output buffer.
//! - [`expr`] — the expression walker and the [`ExprLang`] hooks.
//! - [`dialect`] — the [`Dialect`] trait and the generic expression [`Scope`].
//! - [`steps`] — the [`StepEmitter`] template for decoders and encoders.
//! - [`naming`] — identifier case conversion.
//! - [`union`] — arm tests and names for tagged unions.

pub mod buffers;
pub mod consts;
pub mod dialect;
pub mod expr;
pub mod naming;
pub mod options;
pub mod out;
pub mod steps;
pub mod union;

/// A runtime's source for a module: the parts between `@versions{` and
/// `@versions}` comment lines only when the module has protocol versions.
/// The marker lines always go, and so does the blank line after a dropped
/// part.
pub fn runtime_source(text: &str, versioned: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    let mut dropped = false;
    for line in text.split_inclusive('\n') {
        if line.contains("@versions{") {
            skipping = !versioned;
        } else if line.contains("@versions}") {
            dropped = skipping;
            skipping = false;
        } else if dropped && line.trim().is_empty() {
            dropped = false;
        } else if !skipping {
            dropped = false;
            out.push_str(line);
        }
    }
    out
}

pub use consts::{ConstEmitter, const_pascal, member_category};
pub use dialect::{Dialect, Scope, param_var};
pub use expr::{ExprLang, Mode, cmp_symbol, emit_expr, mark_var};
pub use naming::{magic_literal, pascal_case, string_literal};
pub use options::GenOptions;
pub use out::Out;
pub use steps::{PREFIX_LEN, StepEmitter, mask};
