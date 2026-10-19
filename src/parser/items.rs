//! Packets and their items: fields, bitfields, calculated fields and `align`.

use pest::iterators::Pair;

use super::expr::parse_expr;
use super::types::{to_endianness, type_from_name};
use super::{Rule, int_literal, span_of};
use crate::ast::{
    ArrayLength, BitOrder, BitfieldExpr, BitfieldMember, CalculatedField, Endianness, ExprNode, PacketExpr, PacketItem,
    TypeExpr, TypeNode,
};

fn parse_alignment(pair: Pair<Rule>) -> u64 {
    pair.into_inner().find(|p| p.as_rule() == Rule::numeric_constant).map(|n| int_literal(n.as_str())).unwrap_or(1)
}

/// Builds the parse tree's packets; type names depend on the file's word size.
pub(super) struct TreeBuilder {
    pub word_size: u32,
}

impl TreeBuilder {
    fn type_from_name(&self, name: &str) -> TypeNode {
        type_from_name(name, self.word_size)
    }

    pub fn packets(&self, packets: Pair<Rule>) -> Vec<PacketExpr> {
        let mut results = Vec::<PacketExpr>::new();
        if packets.as_rule() == Rule::packets {
            for packet in packets.into_inner() {
                if packet.as_rule() == Rule::packet {
                    results.push(self.packet(packet));
                }
            }
        }
        results
    }

    fn packet(&self, packet: Pair<Rule>) -> PacketExpr {
        let span = span_of(&packet);
        let mut items = Vec::<PacketItem>::new();
        let mut identifier = String::new();
        let mut packet_endianness: Option<Endianness> = None;
        let mut packet_align: Option<u64> = None;

        for detail in packet.into_inner() {
            match detail.as_rule() {
                Rule::identifier => identifier = detail.as_str().to_string(),
                Rule::endianness => packet_endianness = to_endianness(detail.as_str()),
                Rule::alignment => packet_align = Some(parse_alignment(detail)),
                Rule::rule_list => {
                    for rule in detail.into_inner() {
                        if rule.as_rule() != Rule::rule {
                            continue;
                        }
                        for elem in rule.into_inner() {
                            match elem.as_rule() {
                                Rule::declaration => items.push(PacketItem::Field(self.declaration(elem))),
                                Rule::bitfield_declaration => items.push(PacketItem::Bitfield(self.bitfield(elem))),
                                Rule::calculated_field => {
                                    items.push(PacketItem::Calculated(self.calculated_field(elem)))
                                }
                                Rule::align_directive => {
                                    let span = span_of(&elem);
                                    items.push(PacketItem::Align(parse_alignment(elem), span))
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        PacketExpr { name: identifier, items, endianness: packet_endianness, align: packet_align, span }
    }

    fn declaration(&self, parser_rule: Pair<Rule>) -> TypeExpr {
        let span = span_of(&parser_rule);
        let mut identifier = String::new();
        let mut type_node = TypeNode::UnsignedInteger8;
        let mut array: Option<ArrayLength> = None;
        let mut field_endianness: Option<Endianness> = None;
        let mut align = None;

        for field in parser_rule.into_inner() {
            match field.as_rule() {
                Rule::identifier => identifier = field.as_str().to_string(),
                Rule::field_type => {
                    let inner = field.into_inner().next().expect("field_type has one child");
                    type_node = match inner.as_rule() {
                        Rule::packet_type => TypeNode::Packet(inner.as_str().to_string()),
                        Rule::prefixed_string => {
                            let mut prefix = TypeNode::UnsignedInteger8;
                            let mut endianness = None;
                            for part in inner.into_inner() {
                                match part.as_rule() {
                                    Rule::type_name | Rule::bit_type => prefix = self.type_from_name(part.as_str()),
                                    Rule::endianness => endianness = to_endianness(part.as_str()),
                                    _ => {}
                                }
                            }
                            TypeNode::PrefixedStr { prefix: Box::new(prefix), endianness }
                        }
                        _ => self.type_from_name(inner.as_str()),
                    };
                }
                Rule::alignment => align = Some(parse_alignment(field)),
                Rule::array_specifier => {
                    // array_specifier: "[" expr? "]"
                    array = Some(ArrayLength::Remaining);
                    for inner in field.into_inner() {
                        if inner.as_rule() == Rule::expr {
                            array = Some(ArrayLength::Expr(parse_expr(inner)));
                        }
                    }
                }
                Rule::endianness => field_endianness = to_endianness(field.as_str()),
                _ => {}
            }
        }

        // A bare `bytes` or `string` field (no length) consumes the rest of the input.
        if matches!(type_node, TypeNode::Bytes | TypeNode::Str) && array.is_none() {
            array = Some(ArrayLength::Remaining);
        }

        TypeExpr { id: identifier, expr: type_node, array, endianness: field_endianness, align, span }
    }

    fn bitfield(&self, parser_rule: Pair<Rule>) -> BitfieldExpr {
        let span = span_of(&parser_rule);
        let mut identifier = String::new();
        let mut container = TypeNode::UnsignedInteger8;
        let mut endianness = None;
        let mut order = BitOrder::Msb;
        let mut align = None;
        let mut members = Vec::new();

        for part in parser_rule.into_inner() {
            match part.as_rule() {
                Rule::identifier => identifier = part.as_str().to_string(),
                Rule::type_name | Rule::bit_type => container = self.type_from_name(part.as_str()),
                Rule::endianness => endianness = to_endianness(part.as_str()),
                Rule::bit_order => order = if part.as_str() == "lsb" { BitOrder::Lsb } else { BitOrder::Msb },
                Rule::alignment => align = Some(parse_alignment(part)),
                Rule::bitfield_member => {
                    let mspan = span_of(&part);
                    let mut name = String::new();
                    let mut width = 0;
                    let mut signed = false;
                    for m in part.into_inner() {
                        match m.as_rule() {
                            Rule::identifier => name = m.as_str().to_string(),
                            Rule::bit_type => {
                                if let TypeNode::Bits { width: w, signed: s } = self.type_from_name(m.as_str()) {
                                    width = w;
                                    signed = s;
                                }
                            }
                            _ => {}
                        }
                    }
                    members.push(BitfieldMember { name, width, signed, span: mspan });
                }
                _ => {}
            }
        }

        BitfieldExpr { id: identifier, container, endianness, order, align, members, span }
    }

    fn calculated_field(&self, parser_rule: Pair<Rule>) -> CalculatedField {
        let span = span_of(&parser_rule);
        let mut identifier = String::new();
        let mut type_name = String::new();
        let mut option_expr: Option<ExprNode> = None;

        for field in parser_rule.into_inner() {
            match field.as_rule() {
                Rule::identifier => identifier = field.as_str().to_string(),
                Rule::type_name | Rule::bit_type => type_name = field.as_str().to_string(),
                Rule::expr => option_expr = Some(parse_expr(field)),
                _ => {}
            }
        }

        CalculatedField {
            name: identifier,
            data_type: self.type_from_name(&type_name),
            expr: Box::new(option_expr.expect("calc field must have an expression")),
            span,
        }
    }
}
