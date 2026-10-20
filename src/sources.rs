//! The source files of a compilation. Every file gets a base offset in one
//! shared offset space, so a [`Span`](crate::ast::Span) names its file too.

use std::path::{Path, PathBuf};

pub struct SourceFile {
    /// The name shown in messages (the path as given).
    pub name: String,
    pub path: PathBuf,
    pub text: String,
    /// Where the file starts in the shared offset space.
    pub base: usize,
}

#[derive(Default)]
pub struct SourceMap {
    pub files: Vec<SourceFile>,
}

impl SourceMap {
    /// A map holding one file, at base 0.
    pub fn single(name: &str, text: &str) -> Self {
        let mut map = SourceMap::default();
        map.add(name, Path::new(name), text);
        map
    }

    /// Add a file; returns its base offset.
    pub fn add(&mut self, name: &str, path: &Path, text: &str) -> usize {
        let base = self.files.last().map(|f| f.base + f.text.len() + 1).unwrap_or(0);
        self.files.push(SourceFile { name: name.to_string(), path: path.to_path_buf(), text: text.to_string(), base });
        base
    }

    /// The file holding global offset `offset`.
    pub fn locate(&self, offset: usize) -> Option<&SourceFile> {
        self.files.iter().rev().find(|f| f.base <= offset)
    }
}
