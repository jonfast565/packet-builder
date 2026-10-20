//! Code generators. Each backend lives in its own module and implements
//! [`Backend`]; [`backend`] picks one for a [`Language`].

pub mod c;
pub mod common;
pub mod csharp;
pub mod go;
pub mod python;
pub mod rust;
pub mod wireshark;
pub mod zig;

use crate::Language;
use crate::ir::Module;
use common::GenOptions;

/// A target-language code generator (Strategy).
pub trait Backend {
    /// Source code for every packet of an already validated module.
    fn generate(&self, module: &Module, opts: &GenOptions) -> String;
}

/// The generator for `lang` (Factory).
pub fn backend(lang: Language) -> &'static dyn Backend {
    match lang {
        Language::C => &c::CGenerator,
        Language::Rust => &rust::RustGenerator,
        Language::Zig => &zig::ZigGenerator,
        Language::CSharp => &csharp::CSharpGenerator,
        Language::Python => &python::PythonGenerator,
        Language::Go => &go::GoGenerator,
    }
}
