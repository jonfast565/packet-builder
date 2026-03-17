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

use pest::error::Error;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

use crate::models::parsing_models::{CalculatedField, Endianness, ExprNode, PacketExpr, PacketExprList, TypeExpr, TypeNode};

// ===============================
// Pest Parser
// ===============================

#[derive(Parser)]
#[grammar = "../grammar.pest"]
pub struct PacketParser2;

// Entry point
pub fn parse_file(input: &str) -> Result<PacketExprList, Error<Rule>> {
    let mut pairs = PacketParser2::parse(Rule::packets, input)?;
    let root = pairs.next().expect("packets rule must produce a pair");
    let results = parse_packets(root);
    Ok(PacketExprList { packets: results })
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
    let mut type_rules = Vec::<TypeExpr>::new();
    let mut calculated_fields = Vec::<CalculatedField>::new();
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
                            Rule::declaration => type_rules.push(parse_declaration(elem)),
                            Rule::calculated_field => {
                                calculated_fields.push(parse_calculated_field(elem))
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    PacketExpr {
        name: identifier,
        fields: type_rules,
        calculated_fields,
        endianness: packet_endianness,
    }
}

fn parse_declaration(parser_rule: Pair<Rule>) -> TypeExpr {
    let mut identifier = String::new();
    let mut type_name = String::new();
    let mut array_len_expr: Option<ExprNode> = None;
    let mut field_endianness: Option<Endianness> = None;

    for field in parser_rule.into_inner() {
        match field.as_rule() {
            Rule::identifier => identifier = field.as_str().to_string(),
            Rule::type_name => type_name = field.as_str().to_string(), // actual text like "uint16"
            Rule::array_specifier => {
                // array_specifier: "[" expr "]"
                for inner in field.into_inner() {
                    if inner.as_rule() == Rule::expr {
                        array_len_expr = Some(parse_expr(inner));
                    }
                }
            }
            Rule::endianness => field_endianness = to_endianness_opt(field.as_str()),
            _ => {}
        }
    }

    TypeExpr {
        id: identifier,
        expr: expr_from_type_name(type_name, array_len_expr),
        endianness: field_endianness,
    }
}

fn parse_calculated_field(parser_rule: Pair<Rule>) -> CalculatedField {
    let mut identifier = String::new();
    let mut type_name = String::new();
    let mut option_expr: Option<ExprNode> = None;

    for field in parser_rule.into_inner() {
        match field.as_rule() {
            Rule::identifier => identifier = field.as_str().to_string(),
            Rule::type_name => type_name = field.as_str().to_string(),
            Rule::expr => option_expr = Some(parse_expr(field)),
            _ => {}
        }
    }

    CalculatedField {
        name: identifier,
        data_type: type_name,
        expr: Box::new(option_expr.expect("calc field must have an expression")),
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
    // cmp = { sum ~ ((gte|lte|gt|lt|eq|neq) ~ sum)* }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.clone().into_inner() {
        match item.as_rule() {
            Rule::sum => terms.push(parse_sum(item)),
            Rule::gte | Rule::lte | Rule::gt | Rule::lt | Rule::eq | Rule::neq => {
                ops.push(item.as_rule())
            }
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
    for node in parser_rule.into_inner() {
        return match node.as_rule() {
            Rule::guard_expression => parse_guard_expression(node),
            Rule::literal => parse_literal(node),
            Rule::function_call => parse_function_call(node),
            Rule::accessor => parse_accessor(node),
            Rule::inner_expr => parse_inner_expr(node),
            _ => ExprNode::NoExpr,
        };
    }
    ExprNode::NoExpr
}

fn parse_literal(parser_rule: Pair<Rule>) -> ExprNode {
    for node in parser_rule.into_inner() {
        return match node.as_rule() {
            Rule::numeric_constant => parse_numeric_constant(node),
            Rule::string => ExprNode::StringValue(parse_string_constant(node)),
            _ => ExprNode::NoExpr,
        };
    }
    ExprNode::NoExpr
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
    for p in parser_rule.into_inner() {
        return match p.as_rule() {
            Rule::aggregate_accessor => parse_aggregate_accessor(p),
            Rule::direct_value_accessor => parse_direct_value_accessor(p),
            _ => ExprNode::NoExpr,
        };
    }
    ExprNode::NoExpr
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
    ExprNode::GuardExpression(
        Box::new(exprs[0].clone()),
        Box::new(exprs[1].clone()),
        Box::new(exprs[2].clone()),
    )
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
    if raw.len() >= 2 {
        raw[1..raw.len() - 1].to_string()
    } else {
        String::new()
    }
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

fn expr_from_type_name(type_name: String, array_length: Option<ExprNode>) -> TypeNode {
    match type_name.as_str() {
        "int8" => TypeNode::Integer8(array_length),
        "uint8" => TypeNode::UnsignedInteger8(array_length),
        "int16" => TypeNode::Integer16(array_length),
        "uint16" => TypeNode::UnsignedInteger16(array_length),
        "int32" => TypeNode::Integer32(array_length),
        "uint32" => TypeNode::UnsignedInteger32(array_length),
        "int64" => TypeNode::Integer64(array_length),
        "uint64" => TypeNode::UnsignedInteger64(array_length),
        "float32" => TypeNode::Float32(array_length),
        "float64" => TypeNode::Float64(array_length),
        "macaddress" => TypeNode::MacAddress(array_length),
        "datetime" => TypeNode::DateTime(array_length),
        "bytes" => TypeNode::Bytes(array_length),
        _ => panic!("Not a supported type: {}", type_name),
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
fn to_endianness_opt(s: &str) -> Option<Endianness> {
    to_endianness(s)
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
        let rhs = it_terms
            .next()
            .expect("operator must have a right-hand side term");
        acc = f(acc, rhs, op);
    }
    acc
}
