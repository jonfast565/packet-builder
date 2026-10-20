//! packet-builder: a small language for describing binary packets, and code
//! generators that turn it into parsers/serializers for several languages.

pub mod ast;
pub mod errors;
pub mod generators;
pub mod ir;
mod language;
pub mod parser;
pub mod pcap;

pub use errors::CompileError;
pub use generators::common::GenOptions;
pub use language::Language;

/// Parse and validate a packet description.
pub fn compile(source: &str) -> Result<ir::Module, CompileError> {
    let parsed = parser::parse_file(source)?;
    ir::analyze(&parsed).map_err(CompileError::Semantic)
}

/// Generate source code for an already validated module.
pub fn generate_module(module: &ir::Module, lang: Language, opts: &GenOptions) -> String {
    generators::backend(lang).generate(module, opts)
}

/// Parse, validate and generate in one call.
pub fn generate(source: &str, lang: Language, opts: &GenOptions) -> Result<String, CompileError> {
    let module = compile(source)?;
    Ok(generate_module(&module, lang, opts))
}
