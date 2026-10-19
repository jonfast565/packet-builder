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
