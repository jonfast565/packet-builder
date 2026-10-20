//! Options that affect generated code.

#[derive(Debug, Clone)]
pub struct GenOptions {
    /// Go package / C# namespace / C header guard stem.
    pub package: String,
    /// Decoded byte buffers (and, where the language allows, strings) refer
    /// to the input instead of copying it (`--zero-copy`).
    pub zero_copy: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions { package: "packets".to_string(), zero_copy: false }
    }
}
