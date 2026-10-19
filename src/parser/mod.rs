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

use crate::ast::{PacketExprList, Span};

#[derive(Parser)]
#[grammar = "../grammar.pest"]
pub struct PacketParser;

// Entry point
#[allow(clippy::result_large_err)] // pest's error type; returned once per parse
pub fn parse_file(input: &str) -> Result<PacketExprList, Error<Rule>> {
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
    let packets = builder.packets(root);
    Ok(PacketExprList { packets, constants, word_size })
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

fn span_of(pair: &Pair<Rule>) -> Span {
    let s = pair.as_span();
    Span { start: s.start(), end: s.end() }
}
