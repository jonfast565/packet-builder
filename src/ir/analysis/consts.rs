//! Named constants: folds `const` declarations into a table that packets can
//! refer to, and checks the `: Category` tags on fields.

use std::collections::HashMap;

use super::context::Ctx;
use super::params::Sigs;
use super::types::{type_label, value_type};
use super::versions::{VRange, resolve_ends, version_test};
use crate::ast::{ConstDecl, ConstItem, ConstKind, PacketExpr, PacketExprList, Span, TypeNode};
use crate::errors::Diagnostic;
use crate::ir::expr::{TExpr, Ty};
use crate::ir::model::{Category, ConstVersion, Constant, ValueType};

/// Every constant of a file, in source order.
#[derive(Debug, Default)]
pub(super) struct ConstTable {
    pub constants: Vec<Constant>,
    pub categories: Vec<Category>,
    /// `version N`: the latest protocol version, if the file has versions.
    pub latest: Option<u32>,
}

/// Names that generated code already uses at file level (compared after
/// [`fold_name`]): C# keeps standalone constants in a `Constants` class; the
/// rest are modules, types and macros the generated files rely on (Python,
/// Go and Zig imports, C# base class library types, C standard macros).
const RESERVED: &[&str] = &[
    "constants",
    // Python, Go, Zig
    "math",
    "struct",
    "field",
    "dataclass",
    "list",
    "annotations",
    "std",
    "fmt",
    "utf8",
    "valueerror",
    "overflowerror",
    "unicodedecodeerror",
    "exception",
    // C#
    "system",
    "array",
    "bitconverter",
    "utf8encoding",
    "collections",
    "linq",
    "string",
    "object",
    // C
    "null",
    "eof",
    "true",
    "false",
    "nan",
    "infinity",
    "hugeval",
    "randmax",
    "exitsuccess",
    "exitfailure",
    "errno",
    "assert",
    "sizemax",
    "ptrdiffmax",
    "ptrdiffmin",
];

/// `INT8_MAX`, `UINT64_C`, ...: the `<stdint.h>` macros.
fn is_stdint_macro(key: &str) -> bool {
    let rest = key.strip_prefix('u').unwrap_or(key);
    let Some(rest) = rest.strip_prefix("intmax").or_else(|| rest.strip_prefix("int")) else { return false };
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix("least").or_else(|| rest.strip_prefix("fast")).unwrap_or(rest);
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    matches!(rest, "max" | "min" | "c")
}

/// Generated code changes the case of names and drops underscores
/// (`keep_alive` is `KeepAlive` in Go, `KEEP_ALIVE` in C), so two names that
/// fold to the same string would collide in some language.
fn fold_name(name: &str) -> String {
    name.chars().filter(|c| *c != '_').flat_map(char::to_lowercase).collect()
}

impl ConstTable {
    pub fn build(list: &PacketExprList, diags: &mut Vec<Diagnostic>) -> ConstTable {
        let mut table = ConstTable { latest: super::versions::latest(list), ..Default::default() };
        // An empty packet to type-check values in: no fields, so only constants resolve.
        let scope = PacketExpr {
            name: String::new(),
            params: Vec::new(),
            items: Vec::new(),
            endianness: None,
            align: None,
            versions: Vec::new(),
            span: Span::default(),
        };
        // Folded name -> what it names, for collision messages.
        let mut taken = HashMap::<String, String>::new();
        for p in &list.packets {
            taken.insert(fold_name(&p.name), format!("packet `{}`", p.name));
            taken
                .insert(fold_name(&format!("decode{}", p.name)), format!("the decode function of packet `{}`", p.name));
        }
        let mut claim = |name: &str, what: String, span: Span, diags: &mut Vec<Diagnostic>| {
            let key = fold_name(name);
            let reserved = RESERVED.contains(&key.as_str()) || key.starts_with("pb") || is_stdint_macro(&key);
            if reserved {
                diags.push(Diagnostic::new(format!("{} is reserved by generated code; rename it", what), span));
            } else if let Some(other) = taken.get(&key) {
                diags.push(
                    Diagnostic::new(format!("{} clashes with {} in generated code", what, other), span)
                        .with_note("generated names ignore case and underscores"),
                );
            } else {
                taken.insert(key, what);
            }
        };

        // Re-declarations of a standalone constant for other versions.
        let mut singles = HashMap::<&str, Vec<&ConstDecl>>::new();
        for decl in &list.constants {
            if matches!(decl.kind, ConstKind::Single(_)) {
                singles.entry(decl.name.as_str()).or_default().push(decl);
            }
        }
        for decl in &list.constants {
            let Some(ty) = table.const_type(decl, diags) else { continue };
            match &decl.kind {
                ConstKind::Single(item) => {
                    let decls = &singles[decl.name.as_str()];
                    let versioned = table.latest.is_some() && decls.iter().any(|d| d.versions.is_some());
                    if versioned && !std::ptr::eq(decls[0], decl) {
                        continue; // folded with the first declaration
                    }
                    claim(&decl.name, format!("constant `{}`", decl.name), decl.span, diags);
                    let c = if versioned {
                        let items: Vec<(&ConstItem, Option<crate::ast::VersionRange>)> = decls
                            .iter()
                            .filter_map(|d| match &d.kind {
                                ConstKind::Single(i) => Some((i, d.versions)),
                                _ => None,
                            })
                            .collect();
                        table.fold_versions(&items, &ty, &scope, &format!("constant `{}`", decl.name), diags)
                    } else {
                        table.fold(item, &ty, &scope, diags)
                    };
                    if let Some(c) = c {
                        table.constants.push(c);
                    }
                }
                ConstKind::Group(items) => {
                    claim(&decl.name, format!("category `{}`", decl.name), decl.span, diags);
                    if !decl.name.starts_with(|c: char| c.is_ascii_uppercase()) {
                        diags.push(
                            Diagnostic::new(
                                format!("category `{}` must start with an uppercase letter", decl.name),
                                decl.span,
                            )
                            .with_note("categories become type names in generated code, like packets"),
                        );
                    }
                    let mut members = Vec::<Constant>::new();
                    for (k, item) in items.iter().enumerate() {
                        // Re-declarations of a member for other versions.
                        let same: Vec<&ConstItem> = items.iter().filter(|i| i.name == item.name).collect();
                        if table.latest.is_some() && same.len() > 1 && same.iter().any(|i| i.versions.is_some()) {
                            if !std::ptr::eq(same[0], &items[k]) {
                                continue;
                            }
                            claim(
                                &format!("{}{}", decl.name, item.name),
                                format!("`{}.{}`", decl.name, item.name),
                                item.span,
                                diags,
                            );
                            let pairs: Vec<_> = same.iter().map(|i| (*i, i.versions)).collect();
                            let what = format!("`{}.{}`", decl.name, item.name);
                            if let Some(c) = table.fold_versions(&pairs, &ty, &scope, &what, diags) {
                                members.push(c);
                            }
                            continue;
                        }
                        if fold_name(&item.name) == fold_name(&decl.name) {
                            diags.push(Diagnostic::new(
                                format!("`{}` has the same name as its category `{}`", item.name, decl.name),
                                item.span,
                            ));
                            continue;
                        }
                        if let Some(prev) = members.iter().find(|m| fold_name(&m.name) == fold_name(&item.name)) {
                            diags.push(Diagnostic::new(
                                format!("`{}` is declared more than once in category `{}`", prev.name, decl.name),
                                item.span,
                            ));
                            continue;
                        }
                        claim(
                            &format!("{}{}", decl.name, item.name),
                            format!("`{}.{}`", decl.name, item.name),
                            item.span,
                            diags,
                        );
                        let folded = match item.versions {
                            Some(r) if table.latest.is_some() => {
                                let what = format!("`{}.{}`", decl.name, item.name);
                                table.fold_versions(&[(item, Some(r))], &ty, &scope, &what, diags)
                            }
                            _ => table.fold(item, &ty, &scope, diags),
                        };
                        if let Some(c) = folded {
                            members.push(c);
                        }
                    }
                    table.categories.push(Category { name: decl.name.clone(), ty, members });
                }
            }
        }
        table
    }

    /// The declared type, which must be an integer type.
    fn const_type(&self, decl: &ConstDecl, diags: &mut Vec<Diagnostic>) -> Option<ValueType> {
        match decl.ty {
            TypeNode::Bytes | TypeNode::Char | TypeNode::DateTime => {}
            ref t if t.integer_info().is_some() => return Some(value_type(t)),
            _ => {}
        }
        diags.push(Diagnostic::new(
            format!("constant `{}` must have an integer type, not {}", decl.name, type_label(&decl.ty)),
            decl.span,
        ));
        None
    }

    /// Evaluate one value; it may use the constants declared before it.
    fn fold(
        &self,
        item: &ConstItem,
        ty: &ValueType,
        scope: &PacketExpr,
        diags: &mut Vec<Diagnostic>,
    ) -> Option<Constant> {
        let done = HashMap::new();
        let sigs = Sigs::new();
        let mut ctx = Ctx::new(scope, &done, &sigs, self);
        let value = ctx.check_expr(&item.value, item.span);
        diags.append(&mut ctx.diags);
        let value = value?.const_int();
        let Some(value) = value else {
            diags.push(Diagnostic::new(
                format!("the value of `{}` must be a constant integer expression", item.name),
                item.span,
            ));
            return None;
        };
        if !ty.holds(value) {
            diags.push(Diagnostic::new(
                format!("the value {} of `{}` does not fit its type {}", value, item.name, value_label(ty)),
                item.span,
            ));
            return None;
        }
        Some(Constant {
            name: item.name.clone(),
            ty: ty.clone(),
            value,
            radix: item.radix,
            note: item.note.clone(),
            versions: Vec::new(),
        })
    }

    /// One constant from its declarations for different versions: the
    /// value of each range, and the latest one's (or, when the constant no
    /// longer exists, the last one's) as `value`.
    fn fold_versions(
        &self,
        items: &[(&ConstItem, Option<crate::ast::VersionRange>)],
        ty: &ValueType,
        scope: &PacketExpr,
        what: &str,
        diags: &mut Vec<Diagnostic>,
    ) -> Option<Constant> {
        let latest = self.latest.expect("versioned");
        let decls: Vec<_> = items.iter().map(|(i, r)| (*r, i.span)).collect();
        let ranges: Vec<VRange> = resolve_ends(&decls, latest, what, diags);
        let mut versions = Vec::new();
        for ((item, _), r) in items.iter().zip(&ranges) {
            let c = self.fold(item, ty, scope, diags)?;
            versions.push(ConstVersion { from: r.from, to: r.to, value: c.value, radix: c.radix });
        }
        versions.sort_by_key(|v| v.from);
        let current = versions.iter().find(|v| v.to >= latest).or(versions.last()).cloned()?;
        let first = items[0].0;
        let note = items.iter().rev().find_map(|(i, _)| i.note.clone());
        Some(Constant {
            name: first.name.clone(),
            ty: ty.clone(),
            value: current.value,
            radix: current.radix,
            note,
            versions,
        })
    }

    /// A constant's value in an expression: a literal, or for a versioned
    /// constant the value for the version being coded.
    pub fn value_expr(&self, c: &Constant) -> TExpr {
        let (Some(latest), Some((last, rest))) = (self.latest, c.versions.split_last()) else {
            return TExpr::IntLit(c.value);
        };
        if rest.iter().all(|v| v.value == last.value) {
            return TExpr::IntLit(last.value);
        }
        rest.iter().rev().fold(TExpr::IntLit(last.value), |other, v| TExpr::Guard {
            cond: Box::new(version_test(VRange { from: v.from, to: v.to }, latest)),
            then: Box::new(TExpr::IntLit(v.value)),
            other: Box::new(other),
            ty: Ty::Int,
        })
    }

    pub fn single(&self, name: &str) -> Option<&Constant> {
        self.constants.iter().find(|c| c.name == name)
    }

    pub fn category(&self, name: &str) -> Option<&Category> {
        self.categories.iter().find(|c| c.name == name)
    }

    /// `group.name`, or why it does not exist.
    pub fn member(&self, group: &str, name: &str) -> Result<&Constant, String> {
        let cat = self.category(group).ok_or_else(|| format!("unknown category `{}`", group))?;
        cat.members.iter().find(|m| m.name == name).ok_or_else(|| {
            let names: Vec<_> = cat.members.iter().map(|m| m.name.as_str()).collect();
            format!("category `{}` has no constant `{}` (it has {})", group, name, names.join(", "))
        })
    }
}

fn value_label(ty: &ValueType) -> String {
    match ty {
        ValueType::Int { width, signed } => format!("{}{}", if *signed { "i" } else { "u" }, width),
        _ => "(not an integer)".into(),
    }
}

impl Ctx<'_> {
    /// Record a member's `: Category` tag; every value of the category must fit the member.
    pub fn tag(&mut self, name: &str, tag: &Option<(String, Span)>) {
        let Some((cat_name, span)) = tag else { return };
        let Some(&idx) = self.names.get(name) else { return };
        let Some(cat) = self.consts.category(cat_name) else {
            let note = if self.consts.single(cat_name).is_some() {
                format!(
                    "`{}` is a single constant; tags name a category (`const {} uint8 {{ a = 1, ... }}`)",
                    cat_name, cat_name
                )
            } else {
                "declare it with `const Name uint8 { a = 1, b = 2 }`".to_string()
            };
            self.diags.push(Diagnostic::new(format!("unknown category `{}`", cat_name), *span).with_note(note));
            return;
        };
        let ty = &self.members[idx].ty;
        if !matches!(ty, ValueType::Int { .. }) {
            self.diags.push(Diagnostic::new(
                format!("`{}` is not an integer, so it cannot take values from category `{}`", name, cat_name),
                *span,
            ));
            return;
        }
        if let Some(bad) =
            cat.members.iter().find(|m| !ty.holds(m.value) || m.versions.iter().any(|v| !ty.holds(v.value)))
        {
            self.diags.push(Diagnostic::new(
                format!(
                    "`{}.{}` = {} does not fit `{}` ({})",
                    cat_name,
                    bad.name,
                    bad.literal(),
                    name,
                    value_label(ty)
                ),
                *span,
            ));
            return;
        }
        self.members[idx].category = Some(cat_name.clone());
    }
}
