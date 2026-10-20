//! Loading a file and the files it imports (`import "other.packet"`).
//!
//! Imported files are loaded once, depth first, so their packets and
//! constants come before the importing file's; an import cycle is an error.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ast::{PacketExprList, Span};
use crate::errors::{Diagnostic, parse_diagnostic};
use crate::parser::parse_at;
use crate::sources::SourceMap;

pub struct Loader {
    pub sources: SourceMap,
    pub merged: PacketExprList,
    pub diags: Vec<Diagnostic>,
    /// Files being loaded (an import of one of them is a cycle).
    stack: Vec<PathBuf>,
    done: HashSet<PathBuf>,
}

impl Loader {
    pub fn new() -> Self {
        Loader {
            sources: SourceMap::default(),
            merged: PacketExprList { packets: Vec::new(), constants: Vec::new(), word_size: 16, imports: Vec::new() },
            diags: Vec::new(),
            stack: Vec::new(),
            done: HashSet::new(),
        }
    }

    /// Load `path` (named `name` in messages); `from` is the import that
    /// asked for it. Errors go to `diags`, except that the main file (no
    /// `from`) cannot be read.
    pub fn load(&mut self, name: &str, path: &Path, from: Option<Span>) -> Result<(), String> {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.done.contains(&key) {
            return Ok(());
        }
        if let Some(at) = self.stack.iter().position(|p| *p == key) {
            let chain: Vec<String> = self.stack[at..]
                .iter()
                .chain(std::iter::once(&key))
                .map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
                .collect();
            self.diags.push(Diagnostic::new(format!("import cycle: {}", chain.join(" -> ")), from.unwrap_or_default()));
            return Ok(());
        }
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                let message = format!("cannot read {}: {}", path.display(), e);
                let Some(span) = from else { return Err(message) };
                self.diags.push(Diagnostic::new(message, span));
                return Ok(());
            }
        };
        let base = self.sources.add(name, path, &text);
        let list = match parse_at(&text, base) {
            Ok(l) => l,
            Err(e) => {
                self.diags.push(parse_diagnostic(&e, base));
                return Ok(());
            }
        };
        self.stack.push(key.clone());
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        for (file, span) in &list.imports {
            let target = dir.join(file);
            let shown = target.display().to_string();
            self.load(&shown, &target, Some(*span))?;
        }
        self.stack.pop();
        self.done.insert(key);
        self.merged.packets.extend(list.packets);
        self.merged.constants.extend(list.constants);
        Ok(())
    }
}
