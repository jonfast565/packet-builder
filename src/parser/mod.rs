//! Parser for `.packet` files (grammar in `grammar.pest`).
//!
//! - this file: the pest parser and [`parse_file`];
//! - `literals`: rejects numbers, bit widths and alignments that do not fit,
//!   so the tree walk can assume well-formed values;
//! - `items`: packets, fields, bitfields and calculated fields;
//! - `consts`: file-level named constants and categories;
//! - `expr`: expressions;
//! - `types`: type names (including the word-size dependent aliases).

mod consts;
mod expr;
mod items;
mod literals;
mod types;

use pest::Parser;
use pest::error::Error;
use pest::iterators::Pair;
use pest_derive::Parser;

use crate::ast::{PacketExprList, Span, VersionRange};

#[derive(Parser)]
#[grammar = "../grammar.pest"]
pub struct PacketParser;

thread_local! {
    /// Added to every span: where the file being parsed starts in a
    /// [`SourceMap`](crate::sources::SourceMap).
    static SPAN_BASE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// Entry point
#[allow(clippy::result_large_err)] // pest's error type; returned once per parse
pub fn parse_file(input: &str) -> Result<PacketExprList, Error<Rule>> {
    parse_at(input, 0)
}

/// Parse a file whose spans start at `base` (see [`SourceMap`](crate::sources::SourceMap)).
#[allow(clippy::result_large_err)]
pub fn parse_at(input: &str, base: usize) -> Result<PacketExprList, Error<Rule>> {
    let outer = SPAN_BASE.with(|b| b.replace(base));
    let result = parse_inner(input);
    SPAN_BASE.with(|b| b.set(outer));
    result
}

#[allow(clippy::result_large_err)]
fn parse_inner(input: &str) -> Result<PacketExprList, Error<Rule>> {
    let mut pairs = PacketParser::parse(Rule::packets, input)?;
    let root = pairs.next().expect("packets rule must produce a pair");
    let word_size = root
        .clone()
        .into_inner()
        .find(|p| p.as_rule() == Rule::wordsize_directive)
        .and_then(|d| d.into_inner().find(|p| p.as_rule() == Rule::numeric_constant))
        .map(|n| n.as_str().parse::<u32>().unwrap_or(0))
        .unwrap_or(16);
    literals::check_literals(root.clone(), word_size)?;
    let builder = items::TreeBuilder { word_size };
    let constants = builder.constants(root.clone());
    let imports = root
        .clone()
        .into_inner()
        .filter(|p| p.as_rule() == Rule::import_decl)
        .filter_map(|d| {
            let span = span_of(&d);
            d.into_inner().find(|p| p.as_rule() == Rule::string).map(|s| (expr::parse_string_constant(s), span))
        })
        .collect();
    let dissectors = root.clone().into_inner().filter(|p| p.as_rule() == Rule::dissector_decl).map(dissector).collect();
    let version = root.clone().into_inner().find(|p| p.as_rule() == Rule::version_directive).map(|d| {
        let span = span_of(&d);
        let n = d.into_inner().find(|p| p.as_rule() == Rule::numeric_constant).map(|n| int_literal(n.as_str()));
        (n.unwrap_or(0).min(u32::MAX as u64) as u32, span)
    });
    let packets = builder.packets(root);
    Ok(PacketExprList { packets, constants, word_size, imports, dissectors, version })
}

fn dissector(pair: Pair<Rule>) -> crate::ast::DissectorExpr {
    let mut d = crate::ast::DissectorExpr { span: span_of(&pair), ..Default::default() };
    for part in pair.into_inner() {
        match part.as_rule() {
            Rule::identifier => d.packet = part.as_str().to_string(),
            Rule::dissector_option => {
                let span = span_of(&part);
                let mut inner = part.into_inner();
                let Some(first) = inner.next() else { continue };
                match first.as_rule() {
                    Rule::heuristic_kw => d.heuristic = true,
                    Rule::table_name => {
                        let value = inner.next().map(|v| int_literal(v.as_str())).unwrap_or(0);
                        d.tables.push((first.as_str().to_string(), value));
                    }
                    _ => {
                        let value = inner.next().map(expr::parse_string_constant).unwrap_or_default();
                        d.strings.push((first.as_str().to_string(), value, span));
                    }
                }
            }
            _ => {}
        }
    }
    d
}

/// Parse an integer literal already validated by check_literals.
fn int_literal(s: &str) -> u64 {
    if let Some(rest) = s.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).unwrap_or(0)
    } else if let Some(rest) = s.strip_prefix("0b") {
        u64::from_str_radix(rest, 2).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// `@2..`, `@..3`, `@2..3` or `@2` (from 2 on).
fn version_range(pair: Pair<Rule>) -> VersionRange {
    let span = span_of(&pair);
    let text = pair.as_str().trim_start_matches('@');
    let bound = |s: &str| if s.is_empty() { None } else { Some(s.parse::<u32>().unwrap_or(u32::MAX)) };
    match text.split_once("..") {
        Some((from, to)) => VersionRange { from: bound(from), to: bound(to), span },
        None => VersionRange { from: bound(text), to: None, span },
    }
}

fn span_of(pair: &Pair<Rule>) -> Span {
    let s = pair.as_span();
    let base = SPAN_BASE.with(|b| b.get());
    Span { start: base + s.start(), end: base + s.end() }
}
