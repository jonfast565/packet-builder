// parser.rs
//
// Complete, self-contained parser for the provided grammar.
// - Supports packet- and field-level endianness (le/be)
// - Expression-sized arrays (array_specifier = "[" expr "]")
// - Numbers: decimal, hex (0x...), binary (0b...)
// - Strings, intrinsics, aggregates (sumof/productof), guard expressions
//
// If you already have your own models, replace the models below with your crate's
// and keep the parsing functions as-is (types and constructors are aligned).

use pest::Parser;
use pest::error::Error;
use pest::iterators::Pair;
use pest_derive::Parser;

use crate::models::parsing_models::{
    ArrayLength, BitOrder, BitfieldExpr, BitfieldMember, CalculatedField, Endianness, ExprNode, PacketExpr,
    PacketExprList, PacketItem, Span, TypeExpr, TypeNode,
};

// ===============================
// Pest Parser
// ===============================

#[derive(Parser)]
#[grammar = "../grammar.pest"]
pub struct PacketParser2;

// Entry point
#[allow(clippy::result_large_err)] // pest's error type; returned once per parse
pub fn parse_file(input: &str) -> Result<PacketExprList, Error<Rule>> {
    let mut pairs = PacketParser2::parse(Rule::packets, input)?;
    let root = pairs.next().expect("packets rule must produce a pair");
    check_literals(root.clone())?;
    let results = parse_packets(root);
    Ok(PacketExprList { packets: results })
}

/// Reject numeric literals and bit widths that do not fit, with a located error,
/// so that the tree walk below can assume well-formed values.
#[allow(clippy::result_large_err)]
fn check_literals(pair: Pair<Rule>) -> Result<(), Error<Rule>> {
    for p in pair.into_inner().flatten() {
        let s = p.as_str();
        let ok = match p.as_rule() {
            Rule::numeric_constant => {
                if let Some(rest) = s.strip_prefix("0x") {
                    u64::from_str_radix(rest, 16).is_ok()
                } else if let Some(rest) = s.strip_prefix("0b") {
                    u64::from_str_radix(rest, 2).is_ok()
                } else if s.contains('.') {
                    s.parse::<f64>().is_ok()
                } else {
                    s.parse::<u64>().is_ok()
                }
            }
            Rule::bit_type => matches!(s[1..].parse::<u32>(), Ok(w) if (1..=64).contains(&w)),
            _ => true,
        };
        if !ok {
            let message = match p.as_rule() {
                Rule::bit_type => format!("bit width of `{}` must be between 1 and 64", s),
                _ => format!("numeric literal `{}` does not fit in 64 bits", s),
            };
            return Err(Error::new_from_span(pest::error::ErrorVariant::CustomError { message }, p.as_span()));
        }
    }
    Ok(())
}

fn span_of(pair: &Pair<Rule>) -> Span {
    let s = pair.as_span();
    Span { start: s.start(), end: s.end() }
}

fn parse_packets(packets: Pair<Rule>) -> Vec<PacketExpr> {
    let mut results = Vec::<PacketExpr>::new();
    if packets.as_rule() == Rule::packets {
        for packet in packets.into_inner() {
            if packet.as_rule() == Rule::packet {
                results.push(parse_packet(packet));
            }
        }
    }
    results
}

fn parse_packet(packet: Pair<Rule>) -> PacketExpr {
    let span = span_of(&packet);
    let mut items = Vec::<PacketItem>::new();
    let mut identifier = String::new();
    let mut packet_endianness: Option<Endianness> = None;

    for detail in packet.into_inner() {
        match detail.as_rule() {
            Rule::identifier => identifier = detail.as_str().to_string(),
            Rule::endianness => packet_endianness = to_endianness(detail.as_str()),
            Rule::rule_list => {
                for rule in detail.into_inner() {
                    if rule.as_rule() != Rule::rule {
                        continue;
                    }
                    for elem in rule.into_inner() {
                        match elem.as_rule() {
                            Rule::declaration => items.push(PacketItem::Field(parse_declaration(elem))),
                            Rule::bitfield_declaration => items.push(PacketItem::Bitfield(parse_bitfield(elem))),
                            Rule::calculated_field => items.push(PacketItem::Calculated(parse_calculated_field(elem))),
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    PacketExpr { name: identifier, items, endianness: packet_endianness, span }
}

fn parse_declaration(parser_rule: Pair<Rule>) -> TypeExpr {
    let span = span_of(&parser_rule);
    let mut identifier = String::new();
    let mut type_node = TypeNode::UnsignedInteger8;
    let mut array: Option<ArrayLength> = None;
    let mut field_endianness: Option<Endianness> = None;

    for field in parser_rule.into_inner() {
        match field.as_rule() {
            Rule::identifier => identifier = field.as_str().to_string(),
            Rule::field_type => {
                let inner = field.into_inner().next().expect("field_type has one child");
                type_node = match inner.as_rule() {
                    Rule::packet_type => TypeNode::Packet(inner.as_str().to_string()),
                    _ => type_from_name(inner.as_str()),
                };
            }
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

    // A bare `bytes` field (no length) consumes the rest of the input.
    if type_node == TypeNode::Bytes && array.is_none() {
        array = Some(ArrayLength::Remaining);
    }

    TypeExpr { id: identifier, expr: type_node, array, endianness: field_endianness, span }
}

fn parse_bitfield(parser_rule: Pair<Rule>) -> BitfieldExpr {
    let span = span_of(&parser_rule);
    let mut identifier = String::new();
    let mut container = TypeNode::UnsignedInteger8;
    let mut endianness = None;
    let mut order = BitOrder::Msb;
    let mut members = Vec::new();

    for part in parser_rule.into_inner() {
        match part.as_rule() {
            Rule::identifier => identifier = part.as_str().to_string(),
            Rule::type_name | Rule::bit_type => container = type_from_name(part.as_str()),
            Rule::endianness => endianness = to_endianness(part.as_str()),
            Rule::bit_order => order = if part.as_str() == "lsb" { BitOrder::Lsb } else { BitOrder::Msb },
            Rule::bitfield_member => {
                let mspan = span_of(&part);
                let mut name = String::new();
                let mut width = 0;
                let mut signed = false;
                for m in part.into_inner() {
                    match m.as_rule() {
                        Rule::identifier => name = m.as_str().to_string(),
                        Rule::bit_type => {
                            if let TypeNode::Bits { width: w, signed: s } = type_from_name(m.as_str()) {
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

    BitfieldExpr { id: identifier, container, endianness, order, members, span }
}

fn parse_calculated_field(parser_rule: Pair<Rule>) -> CalculatedField {
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
        data_type: type_from_name(&type_name),
        expr: Box::new(option_expr.expect("calc field must have an expression")),
        span,
    }
}

// ===============================
// Expressions
// ===============================

fn parse_expr(parser_rule: Pair<Rule>) -> ExprNode {
    // entry: expr -> bool_or
    for field in parser_rule.into_inner() {
        if field.as_rule() == Rule::bool_or {
            return parse_bool_or(field);
        }
    }
    ExprNode::NoExpr
}

fn parse_bool_or(parser_rule: Pair<Rule>) -> ExprNode {
    // bool_or = { bool_and ~ (or_kw ~ bool_and )* }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::bool_and => terms.push(parse_bool_and(item)),
            Rule::or_kw => ops.push(Rule::or_kw),
            _ => {}
        }
    }

    fold_left(terms, ops, |lhs, rhs, op| match op {
        Rule::or_kw => ExprNode::Or(Box::new(lhs), Box::new(rhs)),
        _ => unreachable!(),
    })
}

fn parse_bool_and(parser_rule: Pair<Rule>) -> ExprNode {
    // bool_and = { cmp ~ (and_kw ~ cmp )* }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::cmp => terms.push(parse_cmp(item)),
            Rule::and_kw => ops.push(Rule::and_kw),
            _ => {}
        }
    }

    fold_left(terms, ops, |lhs, rhs, op| match op {
        Rule::and_kw => ExprNode::And(Box::new(lhs), Box::new(rhs)),
        _ => unreachable!(),
    })
}

fn parse_cmp(parser_rule: Pair<Rule>) -> ExprNode {
    // cmp = { sum ~ ((neq|gte|lte|gt|lt|eq) ~ sum)? }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::sum => terms.push(parse_sum(item)),
            Rule::gte | Rule::lte | Rule::gt | Rule::lt | Rule::eq | Rule::neq => ops.push(item.as_rule()),
            _ => {}
        }
    }

    // If exactly one operator, build a binary comparison; otherwise just return first term
    if terms.len() == 2 && ops.len() == 1 {
        let lhs = Box::new(terms[0].clone());
        let rhs = Box::new(terms[1].clone());
        return match ops[0] {
            Rule::gt => ExprNode::Gt(lhs, rhs),
            Rule::gte => ExprNode::Gte(lhs, rhs),
            Rule::lt => ExprNode::Lt(lhs, rhs),
            Rule::lte => ExprNode::Lte(lhs, rhs),
            Rule::eq => ExprNode::Equals(lhs, rhs),
            Rule::neq => ExprNode::NotEquals(lhs, rhs),
            _ => ExprNode::NoExpr,
        };
    }

    terms.into_iter().next().unwrap_or(ExprNode::NoExpr)
}

fn parse_sum(parser_rule: Pair<Rule>) -> ExprNode {
    // sum = { product ~ ((plus | minus) ~ product)* }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::product => terms.push(parse_product(item)),
            Rule::plus | Rule::minus => ops.push(item.as_rule()),
            _ => {}
        }
    }

    fold_left(terms, ops, |lhs, rhs, op| match op {
        Rule::plus => ExprNode::Plus(Box::new(lhs), Box::new(rhs)),
        Rule::minus => ExprNode::Minus(Box::new(lhs), Box::new(rhs)),
        _ => unreachable!(),
    })
}

fn parse_product(parser_rule: Pair<Rule>) -> ExprNode {
    // product = { power ~ ((mult | div) ~ power)* }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::power => terms.push(parse_power(item)),
            Rule::mult | Rule::div => ops.push(item.as_rule()),
            _ => {}
        }
    }

    fold_left(terms, ops, |lhs, rhs, op| match op {
        Rule::mult => ExprNode::Mult(Box::new(lhs), Box::new(rhs)),
        Rule::div => ExprNode::Div(Box::new(lhs), Box::new(rhs)),
        _ => unreachable!(),
    })
}

fn parse_power(parser_rule: Pair<Rule>) -> ExprNode {
    // power = { primary ~ (pw ~ primary)? }
    let mut prims = Vec::<ExprNode>::new();
    let mut has_pow = false;

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::primary => prims.push(parse_primary(item)),
            Rule::pw => has_pow = true,
            _ => {}
        }
    }

    if has_pow && prims.len() == 2 {
        ExprNode::Pow(Box::new(prims[0].clone()), Box::new(prims[1].clone()))
    } else {
        prims.into_iter().next().unwrap_or(ExprNode::NoExpr)
    }
}

fn parse_primary(parser_rule: Pair<Rule>) -> ExprNode {
    // primary = { guard_expression | literal | function_call | accessor | inner_expr }
    match parser_rule.into_inner().next() {
        Some(node) => match node.as_rule() {
            Rule::guard_expression => parse_guard_expression(node),
            Rule::literal => parse_literal(node),
            Rule::function_call => parse_function_call(node),
            Rule::accessor => parse_accessor(node),
            Rule::inner_expr => parse_inner_expr(node),
            _ => ExprNode::NoExpr,
        },
        None => ExprNode::NoExpr,
    }
}

fn parse_literal(parser_rule: Pair<Rule>) -> ExprNode {
    match parser_rule.into_inner().next() {
        Some(node) => match node.as_rule() {
            Rule::numeric_constant => parse_numeric_constant(node),
            Rule::string => ExprNode::StringValue(parse_string_constant(node)),
            _ => ExprNode::NoExpr,
        },
        None => ExprNode::NoExpr,
    }
}

fn parse_function_call(parser_rule: Pair<Rule>) -> ExprNode {
    // function_call = { intrinsic_function ~ parameter_list }
    let mut fname = String::new();
    let mut args = Vec::new();
    for p in parser_rule.into_inner() {
        match p.as_rule() {
            Rule::intrinsic_function => fname = p.as_str().to_string(),
            Rule::parameter_list => args = parse_parameter_list(p),
            _ => {}
        }
    }
    ExprNode::ActivationRecord(fname, args)
}

fn parse_accessor(parser_rule: Pair<Rule>) -> ExprNode {
    match parser_rule.into_inner().next() {
        Some(p) => match p.as_rule() {
            Rule::aggregate_accessor => parse_aggregate_accessor(p),
            Rule::direct_value_accessor => parse_direct_value_accessor(p),
            _ => ExprNode::NoExpr,
        },
        None => ExprNode::NoExpr,
    }
}

fn parse_inner_expr(parser_rule: Pair<Rule>) -> ExprNode {
    for value in parser_rule.into_inner() {
        if value.as_rule() == Rule::expr {
            return parse_expr(value);
        }
    }
    ExprNode::NoExpr
}

fn parse_guard_expression(parser_rule: Pair<Rule>) -> ExprNode {
    // when_kw ~ expr ~ then_kw ~ expr ~ otherwise_kw ~ expr
    let mut exprs = Vec::new();
    for value in parser_rule.into_inner() {
        if value.as_rule() == Rule::expr {
            exprs.push(parse_expr(value));
        }
    }
    assert!(exprs.len() == 3, "guard_expression must have 3 sub-expressions");
    ExprNode::GuardExpression(Box::new(exprs[0].clone()), Box::new(exprs[1].clone()), Box::new(exprs[2].clone()))
}

// ===============================
// Terminals/helpers
// ===============================

fn parse_numeric_constant(parser_rule: Pair<Rule>) -> ExprNode {
    let s = parser_rule.as_str();

    // Hex: 0x...
    if let Some(rest) = s.strip_prefix("0x") {
        let v = u64::from_str_radix(rest, 16).expect("invalid hex literal");
        return ExprNode::UnsignedInteger64Value(v);
    }

    // Binary: 0b...
    if let Some(rest) = s.strip_prefix("0b") {
        let v = u64::from_str_radix(rest, 2).expect("invalid binary literal");
        return ExprNode::UnsignedInteger64Value(v);
    }

    // Float
    if s.contains('.') {
        return ExprNode::Float64Value(s.parse::<f64>().expect("invalid float literal"));
    }

    // Decimal (unsigned); note: grammar does not support unary '-'
    ExprNode::UnsignedInteger64Value(s.parse::<u64>().expect("invalid decimal literal"))
}

fn parse_string_constant(parser_rule: Pair<Rule>) -> String {
    // string -> '"' inner '"'
    let raw = parser_rule.as_str();
    if raw.len() >= 2 { raw[1..raw.len() - 1].to_string() } else { String::new() }
}

fn parse_aggregate_accessor(parser_rule: Pair<Rule>) -> ExprNode {
    // (sumof_kw | productof_kw) ~ identifier
    let mut kind: Option<Rule> = None;
    let mut name: Option<String> = None;

    for p in parser_rule.into_inner() {
        match p.as_rule() {
            Rule::sumof_kw | Rule::productof_kw => kind = Some(p.as_rule()),
            Rule::identifier => name = Some(p.as_str().to_string()),
            _ => {}
        }
    }

    match (kind, name) {
        (Some(Rule::sumof_kw), Some(id)) => ExprNode::AggregateSum(id),
        (Some(Rule::productof_kw), Some(id)) => ExprNode::AggregateProduct(id),
        _ => ExprNode::NoExpr,
    }
}

fn parse_direct_value_accessor(parser_rule: Pair<Rule>) -> ExprNode {
    // identifier ~ array_specifier?
    let mut identifier = String::new();
    let mut array_index_expr: Option<Box<ExprNode>> = None;

    for value in parser_rule.into_inner() {
        match value.as_rule() {
            Rule::identifier => identifier = value.as_str().to_string(),
            Rule::array_specifier => {
                for inner in value.into_inner() {
                    if inner.as_rule() == Rule::expr {
                        array_index_expr = Some(Box::new(parse_expr(inner)));
                    }
                }
            }
            _ => {}
        }
    }
    ExprNode::ValueReference(identifier, array_index_expr)
}

#[allow(clippy::vec_box)] // matches ExprNode::ActivationRecord
fn parse_parameter_list(parser_rule: Pair<Rule>) -> Vec<Box<ExprNode>> {
    // lparen ~ (expr ~ (comma ~ expr)*)? ~ comma? ~ rparen
    let mut expression_list = Vec::new();
    for value in parser_rule.into_inner() {
        if value.as_rule() == Rule::expr {
            expression_list.push(Box::new(parse_expr(value)));
        }
    }
    expression_list
}

// ===============================
// Type mapping
// ===============================

fn type_from_name(type_name: &str) -> TypeNode {
    match type_name {
        "int8" => TypeNode::Integer8,
        "uint8" => TypeNode::UnsignedInteger8,
        "int16" => TypeNode::Integer16,
        "uint16" => TypeNode::UnsignedInteger16,
        "int32" => TypeNode::Integer32,
        "uint32" => TypeNode::UnsignedInteger32,
        "int64" => TypeNode::Integer64,
        "uint64" => TypeNode::UnsignedInteger64,
        "float32" => TypeNode::Float32,
        "float64" => TypeNode::Float64,
        "macaddress" => TypeNode::MacAddress,
        "datetime" => TypeNode::DateTime,
        "bytes" => TypeNode::Bytes,
        other => {
            // bit_type: validated by check_literals
            let signed = other.starts_with('i');
            let width = other[1..].parse::<u32>().expect("bit width validated earlier");
            TypeNode::Bits { width, signed }
        }
    }
}

// ===============================
// Utilities
// ===============================

fn to_endianness(s: &str) -> Option<Endianness> {
    match s {
        "le" => Some(Endianness::Le),
        "be" => Some(Endianness::Be),
        _ => None,
    }
}

/// Generic left-fold builder for expression sequences.
fn fold_left<F>(mut terms: Vec<ExprNode>, ops: Vec<Rule>, mut f: F) -> ExprNode
where
    F: FnMut(ExprNode, ExprNode, Rule) -> ExprNode,
{
    if terms.is_empty() {
        return ExprNode::NoExpr;
    }
    if ops.is_empty() {
        return terms.remove(0);
    }
    let mut acc = terms.remove(0);
    let mut it_terms = terms.into_iter();
    for op in ops {
        let rhs = it_terms.next().expect("operator must have a right-hand side term");
        acc = f(acc, rhs, op);
    }
    acc
}
