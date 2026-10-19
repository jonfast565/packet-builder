//! File-level named constants: `const NAME type = value` and categories.

use pest::iterators::Pair;

use super::expr::{parse_expr, parse_string_constant};
use super::items::TreeBuilder;
use super::{Rule, span_of};
use crate::ast::{ConstDecl, ConstItem, ConstKind, ExprNode, Radix, TypeNode};

impl TreeBuilder {
    pub fn constants(&self, packets: Pair<Rule>) -> Vec<ConstDecl> {
        packets.into_inner().filter(|p| p.as_rule() == Rule::const_decl).map(|p| self.const_decl(p)).collect()
    }

    fn const_decl(&self, decl: Pair<Rule>) -> ConstDecl {
        let span = span_of(&decl);
        let mut name = String::new();
        let mut ty = TypeNode::UnsignedInteger8;
        let mut kind = ConstKind::Group(Vec::new());
        for part in decl.into_inner() {
            match part.as_rule() {
                Rule::identifier => name = part.as_str().to_string(),
                Rule::type_name | Rule::bit_type => ty = self.type_from_name(part.as_str()),
                Rule::const_value => kind = ConstKind::Single(const_item(name.clone(), part, span)),
                Rule::const_group => {
                    let members = part
                        .into_inner()
                        .filter(|m| m.as_rule() == Rule::const_member)
                        .map(|m| {
                            let mspan = span_of(&m);
                            let id = m.clone().into_inner().find(|x| x.as_rule() == Rule::identifier);
                            const_item(id.map(|i| i.as_str().to_string()).unwrap_or_default(), m, mspan)
                        })
                        .collect();
                    kind = ConstKind::Group(members);
                }
                _ => {}
            }
        }
        ConstDecl { name, ty, kind, span }
    }
}

/// The value and note of `const_value` / `const_member`.
fn const_item(name: String, pair: Pair<Rule>, span: crate::ast::Span) -> ConstItem {
    let mut value = ExprNode::NoExpr;
    let mut note = None;
    let mut radix = Radix::Dec;
    for part in pair.into_inner() {
        match part.as_rule() {
            Rule::expr => {
                let text = part.as_str().trim();
                value = parse_expr(part);
                if matches!(value, ExprNode::UnsignedInteger64Value(_)) {
                    radix = if text.starts_with("0x") {
                        Radix::Hex
                    } else if text.starts_with("0b") {
                        Radix::Bin
                    } else {
                        Radix::Dec
                    };
                }
            }
            Rule::string => note = Some(parse_string_constant(part)),
            _ => {}
        }
    }
    ConstItem { name, value, note, radix, span }
}
