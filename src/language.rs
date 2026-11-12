//! Target languages.

/// A target language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    C,
    Rust,
    Zig,
    CSharp,
    Python,
    Go,
    Pascal,
    Cobol,
}

impl Language {
    pub const ALL: [Language; 8] = [
        Language::C,
        Language::Rust,
        Language::Zig,
        Language::CSharp,
        Language::Python,
        Language::Go,
        Language::Pascal,
        Language::Cobol,
    ];

    pub fn from_name(name: &str) -> Option<Language> {
        Some(match name.to_ascii_lowercase().as_str() {
            "c" => Language::C,
            "rust" | "rs" => Language::Rust,
            "zig" => Language::Zig,
            "net" | "csharp" | "cs" | "c#" => Language::CSharp,
            "python" | "py" => Language::Python,
            "go" | "golang" => Language::Go,
            "pascal" | "pas" | "delphi" | "fpc" => Language::Pascal,
            "cobol" | "cob" => Language::Cobol,
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
            Language::Pascal => "pascal",
            Language::Cobol => "cobol",
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
            Language::Pascal => "pas",
            Language::Cobol => "cob",
        }
    }
}
