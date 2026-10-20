//! How a field's elements end: `[n]`, `[]`, `[] until cond`, `term ...`,
//! and string encodings.

use super::context::Ctx;
use super::types::field_value_type;
use crate::ast::{ArrayLength, TypeExpr, TypeNode};
use crate::errors::Diagnostic;
use crate::ir::expr::{Ty, coerce};
use crate::ir::model::{Count, ValueType};

impl Ctx<'_> {
    /// The count of field `f`. Strings with a terminator get theirs from
    /// `string_codec` instead.
    pub fn field_count(&mut self, f: &TypeExpr) -> Option<Count> {
        let term = f.term.as_ref().and_then(|(bytes, optional)| self.terminator(bytes, f).map(|t| (t, *optional)));
        let is_str = field_value_type(f) == ValueType::Str;
        if f.id == "_" && (f.until.is_some() || f.term.is_some()) {
            self.diags.push(Diagnostic::new("padding (`_`) cannot use `until` or `term`", f.span));
            return None;
        }
        match (&f.array, &f.until, term) {
            (_, Some(_), Some(_)) => {
                self.diags.push(Diagnostic::new(format!("`{}` cannot have both `until` and `term`", f.id), f.span));
                None
            }
            (Some(ArrayLength::Remaining), Some(cond), None) if !is_str => {
                self.last = Some(field_value_type(f));
                let cond = self.check_expr(cond, f.span);
                self.last = None;
                cond.map(|c| Count::Until(coerce(c, Ty::Bool)))
            }
            (_, Some(_), None) => {
                self.diags.push(
                    Diagnostic::new(format!("`until` on `{}` needs an array without a length", f.id), f.span)
                        .with_note("write `items Item[] until last.kind == 0`"),
                );
                None
            }
            (None, None, Some((term, optional))) if f.expr == TypeNode::Bytes => {
                Some(Count::Terminated { term, optional })
            }
            (None, None, Some(_)) if is_str => None,
            (_, None, Some(_)) => {
                self.diags.push(Diagnostic::new(
                    format!("`term` on `{}` applies to bytes and strings without a length", f.id),
                    f.span,
                ));
                None
            }
            (None, None, None) => None,
            (Some(ArrayLength::Remaining), None, None) => Some(Count::Remaining),
            (Some(ArrayLength::Expr(e)), None, None) => {
                self.check_expr(e, f.span).map(|t| Count::Expr(coerce(t, Ty::Int)))
            }
        }
    }

    /// The bytes of `term`, each 0..=255.
    pub fn terminator(&mut self, bytes: &[u64], f: &TypeExpr) -> Option<Vec<u8>> {
        if let Some(bad) = bytes.iter().find(|b| **b > 255) {
            self.diags.push(Diagnostic::new(format!("terminator byte {} of `{}` is not a byte", bad, f.id), f.span));
            return None;
        }
        Some(bytes.iter().map(|b| *b as u8).collect())
    }

    /// Record a string's encoding (`latin1`, `utf16le`, ...).
    pub fn text_encoding(&mut self, f: &TypeExpr) {
        let Some(enc) = f.encoding else { return };
        let Some(&idx) = self.names.get(&f.id) else { return };
        if field_value_type(f) != ValueType::Str {
            self.diags.push(Diagnostic::new(
                format!("`{}` is not a string, so it cannot have the text encoding `{}`", f.id, enc.name()),
                f.span,
            ));
            return;
        }
        if enc.is_utf16() && (f.expr == TypeNode::CStr || f.term.is_some()) {
            self.diags.push(
                Diagnostic::new(format!("`{}` is UTF-16, so it cannot end at a byte terminator", f.id), f.span)
                    .with_note("give it a length (`string[n]`, `char[n]` or `string(uint16)`)"),
            );
        }
        self.members[idx].encoding = enc;
    }
}
