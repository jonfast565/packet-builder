//! Validation of literal values before the tree walk.

use pest::error::Error;
use pest::iterators::Pair;

use super::types::normalize_type;
use super::{Rule, int_literal};

/// Reject numeric literals and bit widths that do not fit, with a located error,
/// so that the tree walk below can assume well-formed values.
#[allow(clippy::result_large_err)]
pub(super) fn check_literals(pair: Pair<Rule>, word_size: u32) -> Result<(), Error<Rule>> {
    let custom = |message: String, span: pest::Span| {
        Err(Error::new_from_span(pest::error::ErrorVariant::CustomError { message }, span))
    };
    for p in pair.into_inner().flatten() {
        let s = p.as_str();
        match p.as_rule() {
            Rule::wordsize_directive if word_size != 16 && word_size != 32 => {
                return custom("wordsize must be 16 or 32".to_string(), p.as_span());
            }
            Rule::type_name if word_size == 32 && normalize_type(s) == "qword" => {
                return custom(
                    "a quad word would be 128 bits with `wordsize 32`; use uint64 (or dword)".to_string(),
                    p.as_span(),
                );
            }
            Rule::alignment | Rule::align_directive => {
                let n = p.clone().into_inner().find(|x| x.as_rule() == Rule::numeric_constant);
                let ok = n.map(|n| !n.as_str().contains('.') && (1..=4096).contains(&int_literal(n.as_str())));
                if ok != Some(true) {
                    return custom(
                        "alignment must be a whole number of bytes between 1 and 4096".to_string(),
                        p.as_span(),
                    );
                }
            }
            _ => {}
        }
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
