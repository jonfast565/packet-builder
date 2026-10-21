//! Emitting a module's named constants. Every backend implements
//! [`ConstEmitter`]; [`ConstEmitter::emit_constants`] is the shared template
//! that lays out the standalone constants and then each category.

use super::out::Out;
use crate::ir::{Category, Constant, Member, Module};

pub trait ConstEmitter {
    /// Before and after the standalone constants (C# puts them in a class).
    fn open_constants(&self, _out: &mut Out) {}
    fn close_constants(&self, _out: &mut Out) {}

    /// One standalone constant, with its note as a doc comment.
    fn constant(&self, out: &mut Out, c: &Constant);

    /// All standalone constants; override to lay them out as one block.
    fn constants(&self, out: &mut Out, constants: &[Constant]) {
        for c in constants {
            self.constant(out, c);
        }
    }

    /// A whole category.
    fn category(&self, out: &mut Out, cat: &Category);

    /// Blank line(s) between top-level declarations.
    fn separator(&self, out: &mut Out) {
        out.line("");
    }

    /// Emits nothing when the module has no constants, so files without
    /// any keep their exact output.
    fn emit_constants(&self, out: &mut Out, module: &Module) {
        if !module.constants.is_empty() {
            self.separator(out);
            self.open_constants(out);
            self.constants(out, &with_versions(&module.constants));
            self.close_constants(out);
        }
        for cat in &module.categories {
            self.separator(out);
            self.category(out, &Category { members: with_versions(&cat.members), ..cat.clone() });
        }
    }
}

/// Constants whose value changed between protocol versions keep the latest
/// value under their name, and each earlier value as `NAME_V<first version>`
/// (`name_v<first version>` for names with lowercase letters).
pub fn with_versions(constants: &[Constant]) -> Vec<Constant> {
    let mut out = Vec::with_capacity(constants.len());
    for c in constants {
        out.push(c.clone());
        let lower = c.name.chars().any(|ch| ch.is_ascii_lowercase());
        for v in c.versions.iter().filter(|v| v.value != c.value) {
            out.push(Constant {
                name: format!("{}_{}{}", c.name, if lower { "v" } else { "V" }, v.from),
                value: v.value,
                radix: v.radix,
                note: Some(format!("`{}` in versions {}..{}", c.name, v.from, v.to)),
                versions: Vec::new(),
                ..c.clone()
            });
        }
    }
    out
}

/// `keep_alive` / `KEEP_ALIVE` → `KeepAlive`: all-caps names are lowered
/// first so they do not stay shouty in PascalCase languages.
pub fn const_pascal(name: &str) -> String {
    if name.chars().any(|c| c.is_ascii_lowercase()) {
        super::pascal_case(name)
    } else {
        super::pascal_case(&name.to_ascii_lowercase())
    }
}

/// The category a struct member takes its values from.
pub fn member_category(m: &Member) -> Option<&str> {
    m.category.as_deref()
}
