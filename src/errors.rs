use ariadne::{Color, Fmt, Label, Report, ReportKind, Source};
use pest::error::{Error, ErrorVariant, InputLocation};
use pest::Span;

fn span_range<'i>(src: &'i str, e: &Error<Rule>) -> std::ops::Range<usize> {
    match &e.location {
        InputLocation::Pos(p) => {
            let i = p.pos();
            i..(i.saturating_add(1))
        }
        InputLocation::Span((s, e)) => s.pos()..e.pos(),
    }
}

pub fn report_with_ariadne(src_name: &str, src: &str, e: Error<Rule>) {
    let range = span_range(src, &e);

    let expected = match &e.variant {
        ErrorVariant::ParsingError { positives, .. } if !positives.is_empty() => {
            let names = positives.iter().map(|r| friendly(*r)).collect::<Vec<_>>();
            format!("expected {}", names.join(", "))
        }
        ErrorVariant::CustomError { message } => message.clone(),
        _ => "parse error".to_string(),
    };

    Report::build(ReportKind::Error, src_name, range.start)
        .with_message("Parse error")
        .with_label(
            Label::new((src_name, range))
                .with_message(expected)
                .with_color(Color::Red),
        )
        .finish()
        .print((src_name, Source::from(src)))
        .unwrap();
}
