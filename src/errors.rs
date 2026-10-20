use std::fmt;

use ariadne::{Color, Label, Report, ReportKind, Source};
use pest::error::{Error, ErrorVariant, InputLocation};

use crate::ast::Span;
use crate::parser::Rule;
use crate::sources::SourceMap;

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
    /// The main file could not be read.
    Load(String),
}

/// A pest error as a diagnostic, in a file starting at `base`.
pub fn parse_diagnostic(e: &Error<Rule>, base: usize) -> Diagnostic {
    let range = span_range(e);
    Diagnostic::new(parse_message(e), Span { start: base + range.start, end: base + range.end })
}

fn parse_message(e: &Error<Rule>) -> String {
    match &e.variant {
        ErrorVariant::ParsingError { positives, .. } if !positives.is_empty() => {
            let names = positives.iter().map(|r| friendly(*r)).collect::<Vec<_>>();
            format!("expected {}", names.join(", "))
        }
        ErrorVariant::CustomError { message } => message.clone(),
        _ => "parse error".to_string(),
    }
}

/// An error from [`compile_file`](crate::compile_file), with the files read.
pub struct FileError {
    pub error: CompileError,
    pub sources: SourceMap,
}

impl FileError {
    /// Render with source snippets from whichever file each error is in.
    pub fn render(&self) -> String {
        self.error.render_sources(&self.sources)
    }
}

impl fmt::Debug for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.error)
    }
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for FileError {}

impl From<Error<Rule>> for CompileError {
    fn from(e: Error<Rule>) -> Self {
        CompileError::Parse(Box::new(e))
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::Parse(e) => write!(f, "{}", e),
            CompileError::Load(m) => write!(f, "{}", m),
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
        self.render_sources(&SourceMap::single(src_name, src))
    }

    /// Render with snippets from the file of each error.
    pub fn render_sources(&self, sources: &SourceMap) -> String {
        let mut out = Vec::<u8>::new();
        match self {
            CompileError::Load(m) => return format!("error: {}\n", m),
            CompileError::Parse(e) => {
                let Some(file) = sources.files.first() else { return format!("{}\n", e) };
                let name = file.name.as_str();
                let range = span_range(e);
                let _ = Report::build(ReportKind::Error, name, range.start)
                    .with_message("Parse error")
                    .with_label(Label::new((name, range)).with_message(parse_message(e)).with_color(Color::Red))
                    .finish()
                    .write((name, Source::from(file.text.as_str())), &mut out);
            }
            CompileError::Semantic(diags) => {
                for d in diags {
                    let Some(file) = sources.locate(d.span.start) else { continue };
                    let (name, src) = (file.name.as_str(), file.text.as_str());
                    let start = d.span.start - file.base;
                    let end = (d.span.end.saturating_sub(file.base)).max(start + 1).min(src.len().max(1));
                    let mut report = Report::build(ReportKind::Error, name, start)
                        .with_message(&d.message)
                        .with_label(Label::new((name, start..end)).with_message(&d.message).with_color(Color::Red));
                    if let Some(note) = &d.note {
                        report = report.with_note(note);
                    }
                    let _ = report.finish().write((name, Source::from(src)), &mut out);
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
