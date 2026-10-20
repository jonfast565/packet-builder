//! Pieces shared by every backend.
//!
//! - [`options`] — [`GenOptions`].
//! - [`consts`] — the [`ConstEmitter`] template for named constants.
//! - [`out`] — the indented output buffer.
//! - [`expr`] — the expression walker and the [`ExprLang`] hooks.
//! - [`dialect`] — the [`Dialect`] trait and the generic expression [`Scope`].
//! - [`steps`] — the [`StepEmitter`] template for decoders and encoders.
//! - [`naming`] — identifier case conversion.

pub mod consts;
pub mod dialect;
pub mod expr;
pub mod naming;
pub mod options;
pub mod out;
pub mod steps;

pub use consts::{ConstEmitter, const_pascal, member_category};
pub use dialect::{Dialect, Scope};
pub use expr::{ExprLang, Mode, cmp_symbol, emit_expr, mark_var};
pub use naming::{magic_literal, pascal_case, string_literal};
pub use options::GenOptions;
pub use out::Out;
pub use steps::{PREFIX_LEN, StepEmitter, mask};
