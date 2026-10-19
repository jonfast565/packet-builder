//! packet-builder: a small language for describing binary packets, and code
//! generators that turn it into parsers/serializers for several languages.

pub mod errors;
pub mod generators;
pub mod ir;
pub mod models;
pub mod parser;

pub use errors::CompileError;
pub use generators::common::GenOptions;

use generators::c_generator::CGenerator;
use generators::go_generator::GoGenerator;
use generators::net_generator::CSharpGenerator;
use generators::python_generator::PythonGenerator;
use generators::rust_generator::RustGenerator;
use generators::zig_generator::ZigGenerator;

/// A target language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    C,
    Rust,
    Zig,
    CSharp,
    Python,
    Go,
}

impl Language {
    pub const ALL: [Language; 6] =
        [Language::C, Language::Rust, Language::Zig, Language::CSharp, Language::Python, Language::Go];

    pub fn from_name(name: &str) -> Option<Language> {
        Some(match name.to_ascii_lowercase().as_str() {
            "c" => Language::C,
            "rust" | "rs" => Language::Rust,
            "zig" => Language::Zig,
            "net" | "csharp" | "cs" | "c#" => Language::CSharp,
            "python" | "py" => Language::Python,
            "go" | "golang" => Language::Go,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Language::C => "c",
            Language::Rust => "rust",
            Language::Zig => "zig",
            Language::CSharp => "csharp",
            Language::Python => "python",
            Language::Go => "go",
        }
    }

    /// File extension of the generated source.
    pub fn extension(&self) -> &'static str {
        match self {
            Language::C => "h",
            Language::Rust => "rs",
            Language::Zig => "zig",
            Language::CSharp => "cs",
            Language::Python => "py",
            Language::Go => "go",
        }
    }
}

/// Parse and validate a packet description.
pub fn compile(source: &str) -> Result<ir::Module, CompileError> {
    let parsed = parser::parse_file(source)?;
    ir::analyze(&parsed).map_err(CompileError::Semantic)
}

/// Generate source code for an already validated module.
pub fn generate_module(module: &ir::Module, lang: Language, opts: &GenOptions) -> String {
    match lang {
        Language::C => CGenerator::generate(module, opts),
        Language::Rust => RustGenerator::generate(module, opts),
        Language::Zig => ZigGenerator::generate(module, opts),
        Language::CSharp => CSharpGenerator::generate(module, opts),
        Language::Python => PythonGenerator::generate(module, opts),
        Language::Go => GoGenerator::generate(module, opts),
    }
}

/// Parse, validate and generate in one call.
pub fn generate(source: &str, lang: Language, opts: &GenOptions) -> Result<String, CompileError> {
    let module = compile(source)?;
    Ok(generate_module(&module, lang, opts))
}
