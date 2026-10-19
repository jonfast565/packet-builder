//! Options that affect generated code.

#[derive(Debug, Clone)]
pub struct GenOptions {
    /// Go package / C# namespace / C header guard stem.
    pub package: String,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions { package: "packets".to_string() }
    }
}
