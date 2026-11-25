//! A category as a Rust enum: `#[repr]` of the category's type, one variant per
//! value, with checked conversions; `flags` categories also get a set type,
//! and named ranges convert to and from their parent.

use super::naming::{ident, scalar_type};
use crate::generators::common::{Out, const_pascal};
use crate::ir::{Category, Constant};

/// `d_eof` → `DEof`; `self` cannot name a variant.
pub fn variant(name: &str) -> String {
    match const_pascal(name).as_str() {
        "Self" => "Self_".into(),
        v => v.to_string(),
    }
}

/// The members that become variants (the first of each value), and the
/// others as `(alias, variant it stands for)`.
fn split_aliases(cat: &Category) -> (Vec<&Constant>, Vec<(&Constant, &Constant)>) {
    let mut variants: Vec<&Constant> = Vec::new();
    let mut aliases = Vec::new();
    for m in &cat.members {
        match variants.iter().find(|v| v.value == m.value) {
            Some(first) => aliases.push((m, *first)),
            None => variants.push(m),
        }
    }
    (variants, aliases)
}

fn doc(out: &mut Out, note: &Option<String>) {
    if let Some(note) = note {
        out.line(format!("/// {}", note));
    }
}

pub fn emit(out: &mut Out, cat: &Category, all: &[Category]) {
    let name = ident(&cat.name);
    let repr = scalar_type(&cat.ty);
    let (variants, aliases) = split_aliases(cat);
    match &cat.parent {
        Some(parent) => out.line(format!("/// Named `{}` values: the [`{}`] values it takes.", cat.name, ident(parent))),
        None => out.line(format!("/// Named `{}` values.", cat.name)),
    }
    out.line("#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]");
    out.line(format!("#[repr({})]", repr));
    out.open(format!("pub enum {} {{", name));
    for v in &variants {
        doc(out, &v.note);
        out.line(format!("{} = {},", variant(&v.name), v.literal()));
    }
    out.close("}");
    out.line("");
    out.open(format!("impl {} {{", name));
    out.line("/// Every value, in declaration order.");
    let list: Vec<String> = variants.iter().map(|v| format!("Self::{}", variant(&v.name))).collect();
    out.line(format!("pub const ALL: &'static [Self] = &[{}];", list.join(", ")));
    out.line("/// Every name the description gives, aliases included, with its number.");
    let names: Vec<String> = cat.members.iter().map(|m| format!("(\"{}\", {})", m.name, m.literal())).collect();
    out.line(format!("pub const NAMES: &'static [(&'static str, {})] = &[{}];", repr, names.join(", ")));
    for (alias, of) in &aliases {
        doc(out, &alias.note);
        out.line(format!("pub const {}: Self = Self::{};", variant(&alias.name), variant(&of.name)));
    }
    out.line("");
    out.line("/// The value's number.");
    out.open(format!("pub const fn number(self) -> {} {{", repr));
    out.line(format!("self as {}", repr));
    out.close("}");
    out.line("");
    out.line("/// The value with this number, if the category names it.");
    out.open(format!("pub const fn from_number(number: {}) -> Option<Self> {{", repr));
    out.open("match number {");
    for v in &variants {
        out.line(format!("{} => Some(Self::{}),", v.literal(), variant(&v.name)));
    }
    out.line("_ => None,");
    out.close("}");
    out.close("}");
    out.line("");
    out.line("/// The name the description gives the value.");
    out.open("pub const fn name(self) -> &'static str {");
    out.open("match self {");
    for v in &variants {
        out.line(format!("Self::{} => \"{}\",", variant(&v.name), v.name));
    }
    out.close("}");
    out.close("}");
    out.close("}");
    out.line("");
    conversions(out, &name, &repr, &variants);
    if let Some(parent) = cat.parent.as_deref().and_then(|p| all.iter().find(|c| c.name == p)) {
        out.line("");
        parent_conversions(out, &name, &variants, parent);
    }
    if cat.flags {
        out.line("");
        flag_set(out, &name, &repr);
    }
}

fn conversions(out: &mut Out, name: &str, repr: &str, variants: &[&Constant]) {
    out.open(format!("impl Default for {} {{", name));
    out.open("fn default() -> Self {");
    out.line(format!("Self::{}", variant(&variants[0].name)));
    out.close("}");
    out.close("}");
    out.line("");
    out.open(format!("impl TryFrom<{}> for {} {{", repr, name));
    out.line(format!("type Error = {};", repr));
    out.open(format!("fn try_from(number: {}) -> Result<Self, {}> {{", repr, repr));
    out.line("Self::from_number(number).ok_or(number)");
    out.close("}");
    out.close("}");
    out.line("");
    out.open(format!("impl From<{}> for {} {{", name, repr));
    out.open(format!("fn from(value: {}) -> {} {{", name, repr));
    out.line(format!("value as {}", repr));
    out.close("}");
    out.close("}");
}

/// A named range widens to its parent and narrows back from it.
fn parent_conversions(out: &mut Out, name: &str, variants: &[&Constant], parent: &Category) {
    let parent_name = ident(&parent.name);
    let (parent_variants, _) = split_aliases(parent);
    out.open(format!("impl From<{}> for {} {{", name, parent_name));
    out.open(format!("fn from(value: {}) -> {} {{", name, parent_name));
    out.open("match value {");
    for v in variants {
        let canonical = parent_variants.iter().find(|p| p.value == v.value).map_or(&v.name, |p| &p.name);
        out.line(format!("{}::{} => {}::{},", name, variant(&v.name), parent_name, variant(canonical)));
    }
    out.close("}");
    out.close("}");
    out.close("}");
    out.line("");
    out.open(format!("impl TryFrom<{}> for {} {{", parent_name, name));
    out.line(format!("type Error = {};", parent_name));
    out.open(format!("fn try_from(value: {}) -> Result<Self, {}> {{", parent_name, parent_name));
    out.line("Self::from_number(value.number()).ok_or(value)");
    out.close("}");
    out.close("}");
}

/// `<Name>Set`: a word of `<Name>` bits that keeps the bits it does not name.
fn flag_set(out: &mut Out, name: &str, repr: &str) {
    let set = format!("{}Set", name);
    out.line(format!("/// A set of [`{}`] bits; bits it does not name are kept.", name));
    out.line("#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]");
    out.line(format!("pub struct {}(pub {});", set, repr));
    out.line("");
    out.open(format!("impl {} {{", set));
    out.line("/// No bits.");
    out.line("pub const EMPTY: Self = Self(0);");
    out.line("");
    out.line("/// Whether every bit of `flag` is set.");
    out.open(format!("pub const fn contains(self, flag: {}) -> bool {{", name));
    out.line(format!("self.0 & (flag as {r}) == flag as {r}", r = repr));
    out.close("}");
    out.line("");
    out.line("/// The set with `flag` added.");
    out.open(format!("pub const fn with(self, flag: {}) -> Self {{", name));
    out.line(format!("Self(self.0 | flag as {})", repr));
    out.close("}");
    out.line("");
    out.line("/// The set with `flag` removed.");
    out.open(format!("pub const fn without(self, flag: {}) -> Self {{", name));
    out.line(format!("Self(self.0 & !(flag as {}))", repr));
    out.close("}");
    out.line("");
    out.line("/// Adds or removes `flag`.");
    out.open(format!("pub fn set(&mut self, flag: {}, on: bool) {{", name));
    out.line("*self = if on { self.with(flag) } else { self.without(flag) };");
    out.close("}");
    out.line("");
    out.line("/// The named flags that are set, in declaration order.");
    out.open(format!("pub fn flags(self) -> impl Iterator<Item = {}> {{", name));
    out.line(format!("{}::ALL.iter().copied().filter(move |flag| self.contains(*flag))", name));
    out.close("}");
    out.close("}");
    out.line("");
    out.open(format!("impl From<{}> for {} {{", name, set));
    out.open(format!("fn from(flag: {}) -> Self {{", name));
    out.line(format!("Self(flag as {})", repr));
    out.close("}");
    out.close("}");
    out.line("");
    out.open(format!("impl FromIterator<{}> for {} {{", name, set));
    out.open(format!("fn from_iter<I: IntoIterator<Item = {}>>(flags: I) -> Self {{", name));
    out.line("flags.into_iter().fold(Self::EMPTY, Self::with)");
    out.close("}");
    out.close("}");
}
