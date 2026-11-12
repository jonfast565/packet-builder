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
    Java,
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
        Language::Java,
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
            "java" | "jvm" => Language::Java,
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
            Language::Java => "java",
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
            Language::Java => "java",
        }
    }

    /// Name of the generated file for package `package`: Java files are
    /// named after their class (`Packets.java`).
    pub fn file_name(&self, package: &str) -> String {
        match self {
            Language::Java => format!("{}.java", crate::generators::common::pascal_case(package)),
            _ => format!("{}.{}", package, self.extension()),
        }
    }
}
