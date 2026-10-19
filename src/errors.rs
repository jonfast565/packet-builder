use std::fmt;

use ariadne::{Color, Label, Report, ReportKind, Source};
use pest::error::{Error, ErrorVariant, InputLocation};

use crate::ast::Span;
use crate::parser::Rule;

/// A semantic problem found after parsing (unknown field, misaligned type, ...).
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    pub message: String,
    pub span: Span,
    pub note: Option<String>,
}

impl Diagnostic {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Diagnostic { message: message.into(), span, note: None }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

#[derive(Debug)]
pub enum CompileError {
    Parse(Box<Error<Rule>>),
    Semantic(Vec<Diagnostic>),
}

impl From<Error<Rule>> for CompileError {
    fn from(e: Error<Rule>) -> Self {
        CompileError::Parse(Box::new(e))
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::Parse(e) => write!(f, "{}", e),
            CompileError::Semantic(diags) => {
                for (i, d) in diags.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }
                    write!(f, "error: {}", d.message)?;
                    if let Some(note) = &d.note {
                        write!(f, " ({})", note)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for CompileError {}

impl CompileError {
    /// Render the error with source snippets (ariadne), suitable for a terminal.
    pub fn render(&self, src_name: &str, src: &str) -> String {
        let mut out = Vec::<u8>::new();
        match self {
            CompileError::Parse(e) => {
                let range = span_range(e);
                let message = match &e.variant {
                    ErrorVariant::ParsingError { positives, .. } if !positives.is_empty() => {
                        let names = positives.iter().map(|r| friendly(*r)).collect::<Vec<_>>();
                        format!("expected {}", names.join(", "))
                    }
                    ErrorVariant::CustomError { message } => message.clone(),
                    _ => "parse error".to_string(),
                };
                let _ = Report::build(ReportKind::Error, src_name, range.start)
                    .with_message("Parse error")
                    .with_label(Label::new((src_name, range)).with_message(message).with_color(Color::Red))
                    .finish()
                    .write((src_name, Source::from(src)), &mut out);
            }
            CompileError::Semantic(diags) => {
                for d in diags {
                    let end = d.span.end.max(d.span.start + 1).min(src.len().max(1));
                    let mut report =
                        Report::build(ReportKind::Error, src_name, d.span.start).with_message(&d.message).with_label(
                            Label::new((src_name, d.span.start..end)).with_message(&d.message).with_color(Color::Red),
                        );
                    if let Some(note) = &d.note {
                        report = report.with_note(note);
                    }
                    let _ = report.finish().write((src_name, Source::from(src)), &mut out);
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

fn span_range(e: &Error<Rule>) -> std::ops::Range<usize> {
    match &e.location {
        InputLocation::Pos(p) => *p..(p.saturating_add(1)),
        InputLocation::Span((s, e)) => *s..*e,
    }
}

fn friendly(r: Rule) -> String {
    match r {
        Rule::identifier => "an identifier".into(),
        Rule::field_type | Rule::type_name => "a type".into(),
        Rule::bit_type => "a bit type such as u3".into(),
        Rule::expr => "an expression".into(),
        Rule::numeric_constant => "a number".into(),
        Rule::packet => "a packet declaration".into(),
        Rule::rule => "a field declaration".into(),
        Rule::bitfield_member => "a bitfield member such as `flag u1`".into(),
        Rule::EOI => "end of input".into(),
        other => format!("{:?}", other).replace('_', " "),
    }
}
