//! Packets and their items: fields, bitfields, calculated fields and `align`.

use pest::iterators::Pair;

use super::expr::parse_expr;
use super::expr::parse_string_constant;
use super::types::{to_endianness, type_from_name};
use super::{Rule, int_literal, span_of};
use crate::ast::{
    ArmExpr, ArrayLength, AssertExpr, AtExpr, BitOrder, BitfieldExpr, BitfieldMember, CalculatedField, Constraint,
    Endianness, ExprNode, FieldRules, PacketExpr, PacketItem, ParamExpr, Span, SwitchExpr, TextEncoding, TypeExpr,
    TypeNode, WindowExpr,
};

fn parse_alignment(pair: Pair<Rule>) -> u64 {
    pair.into_inner().find(|p| p.as_rule() == Rule::numeric_constant).map(|n| int_literal(n.as_str())).unwrap_or(1)
}

/// The category named by `: Category`, and whether it says `strict`.
fn category_tag(pair: Pair<Rule>, rules: &mut FieldRules) -> Option<(String, Span)> {
    let mut name = None;
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::identifier => name = Some((p.as_str().to_string(), span_of(&p))),
            Rule::strict_kw => rules.strict = true,
            _ => {}
        }
    }
    name
}

/// `== value` or `in lo..hi`.
fn constraint(pair: Pair<Rule>) -> Option<Constraint> {
    let range = pair.clone().into_inner().any(|p| p.as_rule() == Rule::in_kw);
    let mut exprs = pair.into_inner().filter(|p| p.as_rule() == Rule::expr).map(parse_expr);
    if range { Some(Constraint::Range(exprs.next()?, exprs.next()?)) } else { Some(Constraint::Equals(exprs.next()?)) }
}

/// Builds the parse tree's packets; type names depend on the file's word size.
pub(super) struct TreeBuilder {
    pub word_size: u32,
}

impl TreeBuilder {
    pub(super) fn type_from_name(&self, name: &str) -> TypeNode {
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
        let mut params = Vec::new();

        for detail in packet.into_inner() {
            match detail.as_rule() {
                Rule::identifier => identifier = detail.as_str().to_string(),
                Rule::param_list => {
                    for param in detail.into_inner().filter(|x| x.as_rule() == Rule::param) {
                        let span = span_of(&param);
                        let mut parts = param.into_inner();
                        let name = parts.next().map(|x| x.as_str().to_string()).unwrap_or_default();
                        let ty = parts.next().map(|x| self.type_from_name(x.as_str())).unwrap_or(TypeNode::Integer64);
                        params.push(ParamExpr { name, ty, span });
                    }
                }
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
                                Rule::assert_directive => items.push(PacketItem::Assert(assert_directive(elem))),
                                Rule::switch_field => items.push(PacketItem::Switch(self.switch_field(elem))),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        PacketExpr { name: identifier, params, items, endianness: packet_endianness, align: packet_align, span }
    }

    fn declaration(&self, parser_rule: Pair<Rule>) -> TypeExpr {
        let span = span_of(&parser_rule);
        let mut identifier = String::new();
        let mut type_node = TypeNode::UnsignedInteger8;
        let mut array: Option<ArrayLength> = None;
        let mut field_endianness: Option<Endianness> = None;
        let mut align = None;
        let mut category = None;
        let mut rules = FieldRules::default();
        let mut derive = None;
        let mut window = None;
        let mut until = None;
        let mut term = None;
        let mut encoding = None;
        let mut args = Vec::new();
        let mut at = None;

        for field in parser_rule.into_inner() {
            match field.as_rule() {
                Rule::identifier => identifier = field.as_str().to_string(),
                Rule::field_type => (type_node, args) = self.field_type(field),
                Rule::at_clause => {
                    let root = field.clone().into_inner().any(|p| p.as_rule() == Rule::root_kw);
                    let offset = field
                        .into_inner()
                        .find(|p| p.as_rule() == Rule::expr)
                        .map(parse_expr)
                        .unwrap_or(ExprNode::NoExpr);
                    at = Some(AtExpr { offset, root });
                }
                Rule::alignment => align = Some(parse_alignment(field)),
                Rule::array_specifier => array = Some(array_specifier(field)),
                Rule::window => window = Some(window_clause(field)),
                Rule::until_clause => until = field.into_inner().find(|p| p.as_rule() == Rule::expr).map(parse_expr),
                Rule::term_clause => {
                    let optional = field.clone().into_inner().any(|p| p.as_rule() == Rule::optional_kw);
                    let bytes = field
                        .into_inner()
                        .filter(|p| p.as_rule() == Rule::numeric_constant)
                        .map(|n| int_literal(n.as_str()))
                        .collect();
                    term = Some((bytes, optional));
                }
                Rule::text_encoding => encoding = TextEncoding::from_name(field.as_str()),
                Rule::endianness => field_endianness = to_endianness(field.as_str()),
                Rule::category_tag => category = category_tag(field, &mut rules),
                Rule::constraint => rules.constraint = constraint(field),
                Rule::lenient_kw => rules.lenient = true,
                Rule::derivation => derive = field.into_inner().find(|p| p.as_rule() == Rule::expr).map(parse_expr),
                _ => {}
            }
        }

        // A bare `bytes` or `string` field (no length) consumes the rest of the input.
        if matches!(type_node, TypeNode::Bytes | TypeNode::Str) && array.is_none() && term.is_none() {
            array = Some(ArrayLength::Remaining);
        }

        TypeExpr {
            id: identifier,
            expr: type_node,
            array,
            endianness: field_endianness,
            align,
            category,
            derive,
            window,
            until,
            term,
            encoding,
            args,
            at,
            rules,
            span,
        }
    }

    /// The type, and the arguments of a packet type.
    fn field_type(&self, field: Pair<Rule>) -> (TypeNode, Vec<ExprNode>) {
        let inner = field.into_inner().next().expect("field_type has one child");
        let ty = match inner.as_rule() {
            Rule::packet_ref => {
                let mut parts = inner.into_inner();
                let name = parts.next().map(|x| x.as_str().to_string()).unwrap_or_default();
                let args = parts
                    .next()
                    .map(|l| l.into_inner().filter(|x| x.as_rule() == Rule::expr).map(parse_expr).collect())
                    .unwrap_or_default();
                return (TypeNode::Packet(name), args);
            }
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
        (ty, Vec::new())
    }

    fn switch_field(&self, pair: Pair<Rule>) -> SwitchExpr {
        let span = span_of(&pair);
        let mut sw = SwitchExpr {
            id: String::new(),
            selector: ExprNode::NoExpr,
            arms: Vec::new(),
            align: None,
            window: None,
            span,
        };
        for part in pair.into_inner() {
            match part.as_rule() {
                Rule::identifier => sw.id = part.as_str().to_string(),
                Rule::expr => sw.selector = parse_expr(part),
                Rule::alignment => sw.align = Some(parse_alignment(part)),
                Rule::window => sw.window = Some(window_clause(part)),
                Rule::switch_arm => {
                    let aspan = span_of(&part);
                    let mut arm =
                        ArmExpr { values: None, name: String::new(), ty: None, args: Vec::new(), span: aspan };
                    let mut array = None;
                    let mut endian = None;
                    for x in part.into_inner() {
                        match x.as_rule() {
                            Rule::arm_values => {
                                arm.values =
                                    Some(x.into_inner().filter(|v| v.as_rule() == Rule::expr).map(parse_expr).collect())
                            }
                            Rule::identifier => arm.name = x.as_str().to_string(),
                            Rule::field_type => {
                                let (t, args) = self.field_type(x);
                                arm.ty = Some((t, None, None));
                                arm.args = args;
                            }
                            Rule::array_specifier => array = Some(array_specifier(x)),
                            Rule::endianness => endian = to_endianness(x.as_str()),
                            _ => {}
                        }
                    }
                    if let Some((t, a, e)) = &mut arm.ty {
                        *a = array;
                        *e = endian;
                        if matches!(t, TypeNode::Bytes) && a.is_none() {
                            *a = Some(ArrayLength::Remaining);
                        }
                    }
                    sw.arms.push(arm);
                }
                _ => {}
            }
        }
        sw
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
                    let mut category = None;
                    let mut rules = FieldRules::default();
                    for m in part.into_inner() {
                        match m.as_rule() {
                            Rule::identifier => name = m.as_str().to_string(),
                            Rule::bit_type => {
                                if let TypeNode::Bits { width: w, signed: s } = self.type_from_name(m.as_str()) {
                                    width = w;
                                    signed = s;
                                }
                            }
                            Rule::category_tag => category = category_tag(m, &mut rules),
                            Rule::constraint => rules.constraint = constraint(m),
                            Rule::lenient_kw => rules.lenient = true,
                            _ => {}
                        }
                    }
                    members.push(BitfieldMember { name, width, signed, category, rules, span: mspan });
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

fn assert_directive(pair: Pair<Rule>) -> AssertExpr {
    let span = span_of(&pair);
    let mut expr = ExprNode::NoExpr;
    let mut source = String::new();
    let mut message = None;
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::expr => {
                source = p.as_str().trim().to_string();
                expr = parse_expr(p);
            }
            Rule::string => message = Some(parse_string_constant(p)),
            _ => {}
        }
    }
    AssertExpr { expr, source, message, span }
}

/// `[expr]` or `[]`.
fn array_specifier(pair: Pair<Rule>) -> ArrayLength {
    pair.into_inner()
        .find(|p| p.as_rule() == Rule::expr)
        .map(|e| ArrayLength::Expr(parse_expr(e)))
        .unwrap_or(ArrayLength::Remaining)
}

/// `size n [exact]`.
fn window_clause(pair: Pair<Rule>) -> WindowExpr {
    let exact = pair.clone().into_inner().any(|p| p.as_rule() == Rule::exact_kw);
    let size = pair.into_inner().find(|p| p.as_rule() == Rule::expr).map(parse_expr).unwrap_or(ExprNode::NoExpr);
    WindowExpr { size, exact }
}
