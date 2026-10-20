//! Commands that work on a validated module rather than generate codecs:
//!
//! - [`doc`]: Markdown reference with bit diagrams;
//! - [`fuzz`]: fuzzing harnesses that round-trip every packet;
//! - [`diff`]: wire compatibility between two versions of a description.

pub mod diff;
pub mod doc;
pub mod fuzz;
