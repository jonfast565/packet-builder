//! `switch Name { header { ... } body size n otherwise x T const ... packet ... }`:
//! a family of packets sharing a header.

use pest::iterators::Pair;

use super::expr::parse_expr;
use super::items::{TreeBuilder, array_specifier, parse_alignment, window_clause};
use super::types::to_endianness;
use super::{Rule, span_of, version_range};
use crate::ast::{ArmExpr, ArrayLength, FamilyDecl, FamilyMember, FamilyTag, PacketExpr, TypeNode};

impl TreeBuilder {
    pub fn families(&self, packets: Pair<Rule>) -> Vec<FamilyDecl> {
        packets.into_inner().filter(|p| p.as_rule() == Rule::family_decl).map(|p| self.family(p)).collect()
    }

    fn family(&self, decl: Pair<Rule>) -> FamilyDecl {
        let span = span_of(&decl);
        let mut header = PacketExpr {
            name: String::new(),
            params: Vec::new(),
            items: Vec::new(),
            endianness: None,
            align: None,
            versions: Vec::new(),
            span,
        };
        let mut family =
            FamilyDecl { header: header.clone(), body: None, other: None, constants: Vec::new(), members: Vec::new() };
        for part in decl.into_inner() {
            match part.as_rule() {
                Rule::identifier => header.name = part.as_str().to_string(),
                Rule::endianness => header.endianness = to_endianness(part.as_str()),
                Rule::alignment => header.align = Some(parse_alignment(part)),
                Rule::family_header => {
                    for x in part.into_inner().filter(|x| x.as_rule() == Rule::rule_list) {
                        self.rule_list(x, &mut header.items, &mut header.versions);
                    }
                }
                Rule::family_body => {
                    family.body = part.into_inner().find(|x| x.as_rule() == Rule::window).map(window_clause)
                }
                Rule::family_other => family.other = Some(self.family_other(part)),
                Rule::const_decl => family.constants.push(self.const_decl(part)),
                Rule::family_member => family.members.push(self.family_member(part)),
                _ => {}
            }
        }
        family.header = header;
        family
    }

    /// `otherwise name Type`: a default arm.
    fn family_other(&self, pair: Pair<Rule>) -> ArmExpr {
        let mut arm = ArmExpr {
            versions: None,
            by_version: Vec::new(),
            values: None,
            name: String::new(),
            ty: None,
            args: Vec::new(),
            span: span_of(&pair),
        };
        let (mut ty, mut array, mut endian) = (None, None, None);
        for x in pair.into_inner() {
            match x.as_rule() {
                Rule::identifier => arm.name = x.as_str().to_string(),
                Rule::field_type => {
                    let (t, args) = self.field_type(x);
                    ty = Some(t);
                    arm.args = args;
                }
                Rule::array_specifier => array = Some(array_specifier(x)),
                Rule::endianness => endian = to_endianness(x.as_str()),
                _ => {}
            }
        }
        if let Some(t) = ty {
            if matches!(t, TypeNode::Bytes) && array.is_none() {
                array = Some(ArrayLength::Remaining);
            }
            arm.ty = Some((t, array, endian));
        }
        arm
    }

    fn family_member(&self, pair: Pair<Rule>) -> FamilyMember {
        let span = span_of(&pair);
        let mut packet = PacketExpr {
            name: String::new(),
            params: Vec::new(),
            items: Vec::new(),
            endianness: None,
            align: None,
            versions: Vec::new(),
            span,
        };
        let mut member = FamilyMember { packet: packet.clone(), versions: None, tags: Vec::new() };
        for part in pair.into_inner() {
            match part.as_rule() {
                Rule::version_range => member.versions = Some(version_range(part)),
                Rule::identifier => packet.name = part.as_str().to_string(),
                Rule::endianness => packet.endianness = to_endianness(part.as_str()),
                Rule::alignment => packet.align = Some(parse_alignment(part)),
                Rule::family_tags => {
                    for tag in part.into_inner().filter(|t| t.as_rule() == Rule::family_tag) {
                        let span = span_of(&tag);
                        let sets = !tag.clone().into_inner().any(|x| x.as_rule() == Rule::in_kw);
                        let mut inner = tag.into_inner();
                        let field = inner.next().map(|x| x.as_str().to_string()).unwrap_or_default();
                        let values = inner.filter(|x| x.as_rule() == Rule::expr).map(parse_expr).collect();
                        member.tags.push(FamilyTag { field, values, sets, span });
                    }
                }
                Rule::rule_list => self.rule_list(part, &mut packet.items, &mut packet.versions),
                _ => {}
            }
        }
        member.packet = packet;
        member
    }
}
