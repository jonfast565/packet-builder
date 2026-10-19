//! Expressions, from lowest to highest precedence:
//! `or`, `and`, comparison, `+ -`, `* /`, `^`, primary.

use pest::iterators::Pair;

use super::Rule;
use crate::ast::ExprNode;

pub(super) fn parse_expr(parser_rule: Pair<Rule>) -> ExprNode {
    // entry: expr -> bool_or
    for field in parser_rule.into_inner() {
        if field.as_rule() == Rule::bool_or {
            return parse_bool_or(field);
        }
    }
    ExprNode::NoExpr
}

/// A left-associative chain `term (op term)*`: the children of `pair` that
/// are `term` are parsed with `parse_term`, those in `ops` are operators, and
/// `build` combines `lhs op rhs`.
fn left_assoc(
    pair: Pair<Rule>,
    term: Rule,
    parse_term: fn(Pair<Rule>) -> ExprNode,
    ops: &[Rule],
    build: fn(Rule, Box<ExprNode>, Box<ExprNode>) -> ExprNode,
) -> ExprNode {
    let mut terms = Vec::<ExprNode>::new();
    let mut found = Vec::<Rule>::new();
    for item in pair.into_inner() {
        let kind = item.as_rule();
        if kind == term {
            terms.push(parse_term(item));
        } else if ops.contains(&kind) {
            found.push(kind);
        }
    }
    fold_left(terms, found, |lhs, rhs, op| build(op, Box::new(lhs), Box::new(rhs)))
}

fn parse_bool_or(parser_rule: Pair<Rule>) -> ExprNode {
    // bool_or = { bool_and ~ (or_kw ~ bool_and )* }
    left_assoc(parser_rule, Rule::bool_and, parse_bool_and, &[Rule::or_kw], |_, a, b| ExprNode::Or(a, b))
}

fn parse_bool_and(parser_rule: Pair<Rule>) -> ExprNode {
    // bool_and = { cmp ~ (and_kw ~ cmp )* }
    left_assoc(parser_rule, Rule::cmp, parse_cmp, &[Rule::and_kw], |_, a, b| ExprNode::And(a, b))
}

fn parse_cmp(parser_rule: Pair<Rule>) -> ExprNode {
    // cmp = { sum ~ ((neq|gte|lte|gt|lt|eq) ~ sum)? }
    let mut terms = Vec::<ExprNode>::new();
    let mut ops = Vec::<Rule>::new();

    for item in parser_rule.into_inner() {
        match item.as_rule() {
            Rule::sum => terms.push(parse_sum(item)),
            Rule::gte | Rule::lte | Rule::gt | Rule::lt | Rule::eq | Rule::neq => ops.push(item.as_rule()),
            _ => {}
        }
    }

    // If exactly one operator, build a binary comparison; otherwise just return first term
    if let ([_, _], [op]) = (&terms[..], &ops[..]) {
        let rhs = Box::new(terms.pop().expect("two terms"));
        let lhs = Box::new(terms.pop().expect("two terms"));
        return match op {
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
    left_assoc(parser_rule, Rule::product, parse_product, &[Rule::plus, Rule::minus], |op, a, b| match op {
        Rule::plus => ExprNode::Plus(a, b),
        _ => ExprNode::Minus(a, b),
    })
}

fn parse_product(parser_rule: Pair<Rule>) -> ExprNode {
    // product = { power ~ ((mult | div) ~ power)* }
    left_assoc(parser_rule, Rule::power, parse_power, &[Rule::mult, Rule::div], |op, a, b| match op {
        Rule::mult => ExprNode::Mult(a, b),
        _ => ExprNode::Div(a, b),
    })
}

fn parse_power(parser_rule: Pair<Rule>) -> ExprNode {
    // power = { primary ~ (pw ~ primary)? }
    let mut prims = Vec::<ExprNode>::new();
    let mut has_pow = false;

    for item in parser_rule.into_inner() {
        match item.as_rule() {
            Rule::primary => prims.push(parse_primary(item)),
            Rule::pw => has_pow = true,
            _ => {}
        }
    }

    if has_pow && prims.len() == 2 {
        let exponent = Box::new(prims.pop().expect("two primaries"));
        ExprNode::Pow(Box::new(prims.pop().expect("two primaries")), exponent)
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
    ExprNode::Call(fname, args)
}

fn parse_accessor(parser_rule: Pair<Rule>) -> ExprNode {
    match parser_rule.into_inner().next() {
        Some(p) => match p.as_rule() {
            Rule::aggregate_accessor => parse_aggregate_accessor(p),
            Rule::qualified_accessor => {
                let mut ids =
                    p.into_inner().filter(|x| x.as_rule() == Rule::identifier).map(|x| x.as_str().to_string());
                match (ids.next(), ids.next()) {
                    (Some(group), Some(name)) => ExprNode::QualifiedReference(group, name),
                    _ => ExprNode::NoExpr,
                }
            }
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
    let [cond, then, other]: [ExprNode; 3] = exprs.try_into().expect("guard_expression must have 3 sub-expressions");
    ExprNode::GuardExpression(Box::new(cond), Box::new(then), Box::new(other))
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

pub(super) fn parse_string_constant(parser_rule: Pair<Rule>) -> String {
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

fn parse_parameter_list(parser_rule: Pair<Rule>) -> Vec<ExprNode> {
    // lparen ~ (expr ~ (comma ~ expr)*)? ~ comma? ~ rparen
    let mut expression_list = Vec::new();
    for value in parser_rule.into_inner() {
        if value.as_rule() == Rule::expr {
            expression_list.push(parse_expr(value));
        }
    }
    expression_list
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
