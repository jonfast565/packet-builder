//! Identifier case conversion shared by the backends.

/// `snake_case` / `camelCase` / `kebab` → `PascalCase`.
pub fn pascal_case(name: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for c in name.chars() {
        if c == '_' || c == '-' {
            upper = true;
            continue;
        }
        if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, 'F');
    }
    out
}

/// A double-quoted string literal that means the same in C, Rust, Go,
/// Python, C# and Zig: `\` and `"` are escaped, and anything other than
/// printable ASCII becomes `?`. `text` may contain the JSON-style escapes of
/// source strings (`\"`, `\n`, ...), which are resolved first.
pub fn string_literal(text: &str) -> String {
    let mut out = String::from("\"");
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        let c = if c == '\\' {
            match chars.next() {
                Some('n' | 't' | 'r' | 'b' | 'f') => ' ',
                Some('u') => {
                    chars.by_ref().take(4).for_each(drop);
                    '?'
                }
                Some(other) => other,
                None => '\\',
            }
        } else {
            c
        };
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => out.push('?'),
        }
    }
    out.push('"');
    out
}

/// The `== value` of a member as a decimal literal of its type (unsigned
/// 64-bit values above `i64::MAX` stay positive), if it has one.
pub fn magic_literal(m: &crate::ir::Member) -> Option<String> {
    let v = m.magic()?;
    Some(if m.ty.is_signed() { v.to_string() } else { (v as u64).to_string() })
}
