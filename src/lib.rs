//! packet-builder: a small language for describing binary packets, and code
//! generators that turn it into parsers/serializers for several languages.

pub mod ast;
pub mod errors;
pub mod generators;
mod imports;
pub mod ir;
mod language;
pub mod parser;
pub mod pcap;
pub mod sources;

pub use errors::{CompileError, FileError};
pub use generators::common::GenOptions;
pub use language::Language;

/// Parse and validate a packet description. It may not import other files
/// (use [`compile_file`]).
pub fn compile(source: &str) -> Result<ir::Module, CompileError> {
    let parsed = parser::parse_file(source)?;
    if let Some((_, span)) = parsed.imports.first() {
        let d = errors::Diagnostic::new("`import` needs a file to resolve paths against; use compile_file", *span);
        return Err(CompileError::Semantic(vec![d]));
    }
    ir::analyze(&parsed).map_err(CompileError::Semantic)
}

/// Parse and validate a packet description file and every file it imports
/// (paths relative to the importing file). The module holds the packets of
/// all of them.
pub fn compile_file(path: &std::path::Path) -> Result<ir::Module, FileError> {
    let mut loader = imports::Loader::new();
    let name = path.display().to_string();
    if let Err(message) = loader.load(&name, path, None) {
        return Err(FileError { error: CompileError::Load(message), sources: loader.sources });
    }
    if !loader.diags.is_empty() {
        return Err(FileError { error: CompileError::Semantic(loader.diags), sources: loader.sources });
    }
    ir::analyze(&loader.merged).map_err(|d| FileError { error: CompileError::Semantic(d), sources: loader.sources })
}

/// Generate source code for an already validated module.
pub fn generate_module(module: &ir::Module, lang: Language, opts: &GenOptions) -> String {
    generators::backend(lang).generate(module, opts)
}

/// A Wireshark Lua dissector registering a protocol for each of
/// `dissectors` (usually `module.dissectors`); `package` names the global
/// table the file exports.
pub fn generate_dissector(module: &ir::Module, dissectors: &[ir::Dissector], package: &str) -> String {
    generators::wireshark::generate(module, dissectors, package)
}

/// Parse, validate and generate in one call.
pub fn generate(source: &str, lang: Language, opts: &GenOptions) -> Result<String, CompileError> {
    let module = compile(source)?;
    Ok(generate_module(&module, lang, opts))
}
