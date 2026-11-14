//! `switch Name { ... }` families, rewritten into ordinary packets before
//! any other pass runs:
//!
//! - every member becomes the packet `Name_Member` and every constant
//!   `Name_X`; references to them (`Name.Member`, `Name.Category.x`,
//!   `Name.X`, or unqualified inside the block) are renamed;
//! - `Name` itself becomes a packet: the header's items, then
//!   `body switch <tags> { ... }` with one arm per tagged member;
//! - a header field some member sets (`when field = v`) is derived: encoding
//!   writes the value of the member the union holds (`ExprNode::Holds`),
//!   or the stored value for other arms (`ExprNode::Stored`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::ast::{
    ArmExpr, ArrayLength, ConstDecl, ConstKind, Constraint, ExprNode, FamilyDecl, PacketExpr, PacketExprList,
    PacketItem, Span, SwitchExpr, TypeNode,
};
use crate::errors::Diagnostic;

/// A family with versions of its own (`version N` in its block): its
/// packets and constants are analyzed against those versions, and coded
/// in a version scope of their own (`Packet::version_scope`).
pub struct Domain {
    pub version: (u32, Span),
    pub packets: HashSet<String>,
    pub constants: HashSet<String>,
}

/// The union member of a family packet.
pub const BODY: &str = "body";

/// What a family declares, for renaming references to it.
struct Scope {
    members: HashSet<String>,
    singles: HashSet<String>,
    categories: HashSet<String>,
}

struct Renamer<'a> {
    families: &'a HashMap<String, Scope>,
    /// The family whose block is being rewritten.
    inside: Option<&'a str>,
    /// Fields and parameters of the packet being rewritten, which hide
    /// constants of the same name.
    locals: HashSet<String>,
    diags: &'a mut Vec<Diagnostic>,
}

fn mangle(family: &str, name: &str) -> String {
    format!("{}_{}", family, name)
}

/// `ServerReady` → `server_ready`.
fn snake_case(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 && !out.ends_with('_') {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

impl Renamer<'_> {
    fn scope(&self) -> Option<(&str, &Scope)> {
        self.inside.map(|f| (f, &self.families[f]))
    }

    fn packet_name(&mut self, name: &mut String, span: Span) {
        if let Some((fam, member)) = name.split_once('.') {
            match self.families.get(fam) {
                Some(s) if s.members.contains(member) => *name = mangle(fam, member),
                Some(_) => {
                    self.diags.push(Diagnostic::new(format!("family `{}` has no packet `{}`", fam, member), span))
                }
                None => self.diags.push(Diagnostic::new(format!("unknown family `{}` in `{}`", fam, name), span)),
            }
        } else if let Some((fam, s)) = self.scope()
            && s.members.contains(name.as_str())
        {
            *name = mangle(fam, name);
        }
    }

    fn category(&mut self, name: &mut String, span: Span) {
        if let Some((fam, cat)) = name.split_once('.') {
            match self.families.get(fam) {
                Some(s) if s.categories.contains(cat) => *name = mangle(fam, cat),
                Some(_) => {
                    self.diags.push(Diagnostic::new(format!("family `{}` has no category `{}`", fam, cat), span))
                }
                None => self.diags.push(Diagnostic::new(format!("unknown family `{}` in `{}`", fam, name), span)),
            }
        } else if let Some((fam, s)) = self.scope()
            && s.categories.contains(name.as_str())
        {
            *name = mangle(fam, name);
        }
    }

    fn ty(&mut self, t: &mut TypeNode, span: Span) {
        if let TypeNode::Packet(name) = t {
            self.packet_name(name, span);
        }
    }

    fn expr(&mut self, e: &mut ExprNode, span: Span) {
        use ExprNode::*;
        match e {
            QualifiedReference(group, name) => {
                if let Some((fam, cat)) = group.split_once('.') {
                    match self.families.get(fam) {
                        Some(s) if s.categories.contains(cat) => *group = mangle(fam, cat),
                        Some(_) => self
                            .diags
                            .push(Diagnostic::new(format!("family `{}` has no category `{}`", fam, cat), span)),
                        None => self.diags.push(Diagnostic::new(format!("unknown family `{}`", fam), span)),
                    }
                } else if let Some(s) = self.families.get(group.as_str()) {
                    if s.singles.contains(name.as_str()) {
                        *e = ValueReference(mangle(group, name), None);
                    } else {
                        self.diags
                            .push(Diagnostic::new(format!("family `{}` has no constant `{}`", group, name), span));
                    }
                } else if let Some((fam, s)) = self.scope()
                    && s.categories.contains(group.as_str())
                {
                    *group = mangle(fam, group);
                }
            }
            ValueReference(name, index) => {
                if let Some(ix) = index {
                    self.expr(ix, span);
                } else if let Some((fam, s)) = self.scope()
                    && s.singles.contains(name.as_str())
                    && !self.locals.contains(name.as_str())
                {
                    *name = mangle(fam, name);
                }
            }
            Call(_, args) => args.iter_mut().for_each(|a| self.expr(a, span)),
            GuardExpression(a, b, c) => {
                self.expr(a, span);
                self.expr(b, span);
                self.expr(c, span);
            }
            Plus(a, b)
            | Minus(a, b)
            | Mult(a, b)
            | Div(a, b)
            | Pow(a, b)
            | Mod(a, b)
            | Shl(a, b)
            | Shr(a, b)
            | BitAnd(a, b)
            | BitOr(a, b)
            | BitXor(a, b)
            | Gt(a, b)
            | Gte(a, b)
            | Lt(a, b)
            | Lte(a, b)
            | Equals(a, b)
            | NotEquals(a, b)
            | And(a, b)
            | Or(a, b) => {
                self.expr(a, span);
                self.expr(b, span);
            }
            Neg(a) | BitNot(a) | Not(a) => self.expr(a, span),
            NoExpr
            | UnsignedInteger64Value(_)
            | Float64Value(_)
            | StringValue(_)
            | RangeCall(..)
            | AggregateSum(_)
            | AggregateProduct(_)
            | Holds(..)
            | Stored(_) => {}
        }
    }

    fn constraint(&mut self, c: &mut Constraint, span: Span) {
        match c {
            Constraint::Equals(e) => self.expr(e, span),
            Constraint::Range(a, b) => {
                self.expr(a, span);
                self.expr(b, span);
            }
            Constraint::Versioned(list) => {
                for (e, c) in list {
                    self.expr(e, span);
                    self.constraint(c, span);
                }
            }
        }
    }

    fn array(&mut self, a: &mut Option<ArrayLength>, span: Span) {
        if let Some(ArrayLength::Expr(e)) = a {
            self.expr(e, span);
        }
    }

    fn arm(&mut self, arm: &mut ArmExpr) {
        let span = arm.span;
        for v in arm.values.iter_mut().flatten() {
            self.expr(v, span);
        }
        for (_, _, vs) in &mut arm.by_version {
            vs.iter_mut().for_each(|v| self.expr(v, span));
        }
        if let Some((t, a, _)) = &mut arm.ty {
            self.ty(t, span);
            self.array(a, span);
        }
        arm.args.iter_mut().for_each(|a| self.expr(a, span));
    }

    fn packet(&mut self, p: &mut PacketExpr) {
        self.locals = p.params.iter().map(|x| x.name.clone()).collect();
        for it in &p.items {
            match it {
                PacketItem::Field(f) => drop(self.locals.insert(f.id.clone())),
                PacketItem::Bitfield(b) => self.locals.extend(b.members.iter().map(|m| m.name.clone())),
                PacketItem::Calculated(c) => drop(self.locals.insert(c.name.clone())),
                PacketItem::Switch(s) => drop(self.locals.insert(s.id.clone())),
                _ => {}
            }
        }
        for it in &mut p.items {
            match it {
                PacketItem::Field(f) => {
                    let span = f.span;
                    self.ty(&mut f.expr, span);
                    self.array(&mut f.array, span);
                    if let Some((c, s)) = &mut f.category {
                        self.category(c, *s);
                    }
                    for e in [&mut f.derive, &mut f.placeholder, &mut f.until].into_iter().flatten() {
                        self.expr(e, span);
                    }
                    if let Some(w) = &mut f.window {
                        self.expr(&mut w.size, span);
                    }
                    f.args.iter_mut().for_each(|a| self.expr(a, span));
                    if let Some(at) = &mut f.at {
                        self.expr(&mut at.offset, span);
                    }
                    if let Some(c) = &mut f.rules.constraint {
                        self.constraint(c, span);
                    }
                }
                PacketItem::Bitfield(b) => {
                    for m in &mut b.members {
                        if let Some((c, s)) = &mut m.category {
                            self.category(c, *s);
                        }
                        if let Some(c) = &mut m.rules.constraint {
                            self.constraint(c, m.span);
                        }
                    }
                }
                PacketItem::Calculated(c) => self.expr(&mut c.expr, c.span),
                PacketItem::Assert(a) => self.expr(&mut a.expr, a.span),
                PacketItem::Switch(s) => {
                    self.expr(&mut s.selector, s.span);
                    s.arms.iter_mut().for_each(|a| self.arm(a));
                    if let Some(w) = &mut s.window {
                        self.expr(&mut w.size, s.span);
                    }
                }
                PacketItem::Override(o) => {
                    for e in [&mut o.derive, &mut o.placeholder].into_iter().flatten() {
                        self.expr(e, o.span);
                    }
                    if let Some(c) = &mut o.rules.constraint {
                        self.constraint(c, o.span);
                    }
                }
                PacketItem::Align(..) => {}
            }
        }
        self.locals.clear();
    }

    fn constant(&mut self, c: &mut ConstDecl) {
        match &mut c.kind {
            ConstKind::Single(item) => self.expr(&mut item.value, item.span),
            ConstKind::Group(items) => items.iter_mut().for_each(|i| self.expr(&mut i.value, i.span)),
        }
    }
}

/// The list with every family turned into packets and constants (the list
/// itself when it has none).
pub fn desugar<'a>(list: &'a PacketExprList, diags: &mut Vec<Diagnostic>) -> (Cow<'a, PacketExprList>, Vec<Domain>) {
    if list.families.is_empty() {
        return (Cow::Borrowed(list), Vec::new());
    }
    let mut domains = Vec::new();
    let mut families = HashMap::new();
    for f in &list.families {
        let name = &f.header.name;
        let mut scope = Scope { members: HashSet::new(), singles: HashSet::new(), categories: HashSet::new() };
        for m in &f.members {
            if !scope.members.insert(m.packet.name.clone()) {
                diags.push(Diagnostic::new(
                    format!("family `{}` declares `{}` more than once", name, m.packet.name),
                    m.packet.span,
                ));
            }
        }
        for c in &f.constants {
            match c.kind {
                ConstKind::Single(_) => scope.singles.insert(c.name.clone()),
                ConstKind::Group(_) => scope.categories.insert(c.name.clone()),
            };
        }
        if families.insert(name.clone(), scope).is_some() {
            diags.push(Diagnostic::new(format!("family `{}` is declared more than once", name), f.header.span));
        }
    }
    check_spellings(list, &families, diags);

    let mut out = list.clone();
    out.families.clear();
    let mut r = Renamer { families: &families, inside: None, locals: HashSet::new(), diags };
    out.packets.iter_mut().for_each(|p| r.packet(p));
    out.constants.iter_mut().for_each(|c| r.constant(c));
    for f in &list.families {
        let fam = f.header.name.as_str();
        r.inside = Some(fam);
        let first_constant = out.constants.len();
        let first_packet = out.packets.len();
        for c in &f.constants {
            let mut c = c.clone();
            r.constant(&mut c);
            c.name = mangle(fam, &c.name);
            if let ConstKind::Single(item) = &mut c.kind {
                item.name = c.name.clone();
            }
            out.constants.push(c);
        }
        let mut members = Vec::new();
        for m in &f.members {
            let mut p = m.packet.clone();
            r.packet(&mut p);
            p.name = mangle(fam, &p.name);
            p.endianness = p.endianness.or(f.header.endianness.clone());
            p.align = p.align.or(f.header.align);
            members.push(p);
        }
        let mut header = f.header.clone();
        r.packet(&mut header);
        let mut f = f.clone();
        for m in &mut f.members {
            r.locals.clear();
            for t in &mut m.tags {
                t.values.iter_mut().for_each(|v| r.expr(v, t.span));
            }
        }
        if let Some(o) = &mut f.other {
            r.arm(o);
        }
        if let Some(w) = &mut f.body {
            r.expr(&mut w.size, f.header.span);
        }
        r.inside = None;
        out.packets.push(family_packet(&f, header, r.diags));
        out.packets.extend(members);
        if let Some(version) = f.version {
            domains.push(Domain {
                version,
                packets: out.packets[first_packet..].iter().map(|p| p.name.clone()).collect(),
                constants: out.constants[first_constant..].iter().map(|c| c.name.clone()).collect(),
            });
        }
    }
    (Cow::Owned(out), domains)
}

/// A family's `Name_X` names must not be taken by other declarations.
fn check_spellings(list: &PacketExprList, families: &HashMap<String, Scope>, diags: &mut Vec<Diagnostic>) {
    let mut taken = HashMap::new();
    for p in &list.packets {
        taken.insert(p.name.as_str(), p.span);
    }
    for c in &list.constants {
        taken.insert(c.name.as_str(), c.span);
    }
    for (fam, s) in families {
        for name in s.members.iter().chain(&s.singles).chain(&s.categories) {
            if let Some(span) = taken.get(mangle(fam, name).as_str()) {
                diags.push(Diagnostic::new(
                    format!("`{}` has the name `{}.{}` takes outside its family", mangle(fam, name), fam, name),
                    *span,
                ));
            }
        }
    }
}

/// `Name`: the header, then the member its tags pick.
fn family_packet(f: &FamilyDecl, mut header: PacketExpr, diags: &mut Vec<Diagnostic>) -> PacketExpr {
    let fam = f.header.name.as_str();
    let tagged: Vec<_> = f.members.iter().filter(|m| !m.tags.is_empty()).collect();

    // The tag fields, in header order, and their widths.
    let mut fields = Vec::<(String, u32)>::new();
    let mut signed = Vec::<&str>::new();
    if let Some(first) = tagged.first() {
        for it in &header.items {
            let PacketItem::Field(h) = it else { continue };
            if !first.tags.iter().any(|t| t.field == h.id) || fields.iter().any(|(n, _)| n == &h.id) {
                continue;
            }
            match h.expr.integer_info() {
                Some((w, sign))
                    if h.array.is_none()
                        && !matches!(h.expr, TypeNode::Varint(_) | TypeNode::Bytes | TypeNode::Char)
                        && h.at.is_none() =>
                {
                    if sign {
                        signed.push(&h.id);
                    }
                    fields.push((h.id.clone(), w))
                }
                _ => diags.push(Diagnostic::new(
                    format!("the tag `{}` must be an integer field of the header (not an array or a varint)", h.id),
                    h.span,
                )),
            }
        }
        for t in &first.tags {
            if !header.items.iter().any(|it| matches!(it, PacketItem::Field(h) if h.id == t.field)) {
                diags.push(Diagnostic::new(format!("the header of `{}` has no field `{}`", fam, t.field), t.span));
            }
        }
    }
    for m in &tagged {
        let mut names: Vec<&str> = m.tags.iter().map(|t| t.field.as_str()).collect();
        names.sort_unstable();
        let mut want: Vec<&str> = tagged[0].tags.iter().map(|t| t.field.as_str()).collect();
        want.sort_unstable();
        if names != want || names.windows(2).any(|w| w[0] == w[1]) {
            diags.push(Diagnostic::new(
                format!("every member of `{}` must tag the same fields once each ({})", fam, want.join(", ")),
                m.packet.span,
            ));
        }
    }
    if fields.len() > 1 {
        for name in &signed {
            diags.push(Diagnostic::new(
                format!("the tag `{}` is signed; tags packed together must be unsigned", name),
                f.header.span,
            ));
        }
    }
    let total: u32 = fields.iter().map(|(_, w)| *w).sum();
    if fields.len() > 1 && total > 63 {
        diags.push(Diagnostic::new(
            format!("the tags of `{}` take {} bits; together they must fit in 63", fam, total),
            f.header.span,
        ));
    }

    // Without a usable tag field there is nothing to dispatch on (the
    // errors are already reported, or there are no tagged members).
    if fields.is_empty() {
        if tagged.is_empty() {
            diags.push(Diagnostic::new(
                format!("family `{}` has no tagged members (`packet X when field = value`)", fam),
                f.header.span,
            ));
        }
        return header;
    }

    // The selector packs the tag fields, the first in the highest bits.
    // Field values already fit their width (and are unsigned); arm values
    // are masked so a value too wide for its field cannot reach the next.
    let pack = |vals: Vec<ExprNode>, mask: bool| -> ExprNode {
        if vals.len() == 1 {
            return vals.into_iter().next().expect("one");
        }
        let mut shift: u32 = fields.iter().map(|(_, w)| *w).sum();
        let mut acc: Option<ExprNode> = None;
        for (v, (_, w)) in vals.into_iter().zip(&fields) {
            shift -= w;
            let mut part = v;
            if mask {
                let m = ExprNode::UnsignedInteger64Value(if *w >= 64 { u64::MAX } else { (1u64 << w) - 1 });
                part = ExprNode::BitAnd(Box::new(part), Box::new(m));
            }
            if shift > 0 {
                part = ExprNode::Shl(Box::new(part), Box::new(ExprNode::UnsignedInteger64Value(shift as u64)));
            }
            acc = Some(match acc {
                None => part,
                Some(a) => ExprNode::BitOr(Box::new(a), Box::new(part)),
            });
        }
        acc.expect("tags")
    };
    let selector = pack(fields.iter().map(|(n, _)| ExprNode::ValueReference(n.clone(), None)).collect(), false);

    let mut arms = Vec::new();
    for m in &tagged {
        if !m.packet.params.is_empty() {
            diags.push(Diagnostic::new(
                format!("`{}.{}` has tags, so it cannot take parameters", fam, m.packet.name),
                m.packet.span,
            ));
        }
        // Every combination of the tags' values.
        let mut combos: Vec<Vec<ExprNode>> = vec![Vec::new()];
        for (field, _) in &fields {
            let Some(t) = m.tags.iter().find(|t| &t.field == field) else { continue };
            combos = combos
                .into_iter()
                .flat_map(|c| {
                    t.values.iter().map(move |v| {
                        let mut c = c.clone();
                        c.push(v.clone());
                        c
                    })
                })
                .collect();
        }
        arms.push(ArmExpr {
            versions: m.versions,
            by_version: Vec::new(),
            values: Some(combos.into_iter().map(|c| pack(c, true)).collect()),
            name: snake_case(&m.packet.name),
            ty: Some((TypeNode::Packet(mangle(fam, &m.packet.name)), None, None)),
            args: Vec::new(),
            span: m.packet.span,
        });
    }
    if let Some(o) = &f.other {
        arms.push(o.clone());
    }

    // Header fields the members set are derived from the arm held.
    for (field, _) in &fields {
        let setters: Vec<(String, &ExprNode)> = tagged
            .iter()
            .filter_map(|m| {
                let t = m.tags.iter().find(|t| &t.field == field && t.sets)?;
                Some((snake_case(&m.packet.name), t.values.first()?))
            })
            .collect();
        if setters.is_empty() {
            continue;
        }
        let mut e = ExprNode::Stored(field.clone());
        // Arms with the same value share one test.
        let mut groups: Vec<(&ExprNode, Vec<String>)> = Vec::new();
        for (arm, v) in setters {
            match groups.iter_mut().find(|(g, _)| *g == v) {
                Some((_, arms)) => arms.push(arm),
                None => groups.push((v, vec![arm])),
            }
        }
        for (v, names) in groups.into_iter().rev() {
            let cond = names
                .into_iter()
                .map(|a| ExprNode::Holds(BODY.to_string(), a))
                .reduce(|a, b| ExprNode::Or(Box::new(a), Box::new(b)))
                .expect("one arm");
            e = ExprNode::GuardExpression(Box::new(cond), Box::new(v.clone()), Box::new(e));
        }
        for it in &mut header.items {
            if let PacketItem::Field(h) = it
                && &h.id == field
            {
                if h.derive.is_some() {
                    diags.push(Diagnostic::new(
                        format!("`{}` is a tag the members set, so it cannot also be derived", field),
                        h.span,
                    ));
                }
                h.derive = Some(e.clone());
            }
        }
    }

    header.items.push(PacketItem::Switch(SwitchExpr {
        id: BODY.to_string(),
        selector,
        arms,
        align: None,
        window: f.body.clone(),
        span: f.header.span,
    }));
    header.versions.push(None);
    header
}
