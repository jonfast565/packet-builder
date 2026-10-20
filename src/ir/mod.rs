//! Semantic analysis: turns the parsed packet list into a validated,
//! language-independent layout that every code generator consumes.
//!
//! - [`model`] — the validated packet model (packets, members, unions).
//! - [`wire`] — how fields travel on the wire (codecs, counts, steps).
//! - [`expr`] — type-checked expressions.
//! - `analysis` — builds the model from the parse tree. It resolves packet
//!   references and rejects cycles, tracks the bit offset of every field so
//!   that byte-oriented types are only used where they are byte aligned,
//!   type-checks expressions and decides when each calculated field can be
//!   evaluated while decoding.
//! - [`layout`] — the field-by-field layout report.
//! - [`interp`] — a reference interpreter that decodes and encodes with a
//!   module directly.

mod analysis;
pub mod expr;
pub mod interp;
pub mod layout;
pub mod model;
pub mod wire;

pub use analysis::analyze;
pub use expr::*;
pub use layout::LayoutRow;
pub use model::*;
