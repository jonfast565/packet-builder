//! Line-oriented output buffer with indentation.

/// Line-oriented output buffer with indentation.
pub struct Out {
    pub buf: String,
    level: usize,
    unit: &'static str,
}

impl Out {
    pub fn new(unit: &'static str) -> Self {
        Out { buf: String::new(), level: 0, unit }
    }

    pub fn line(&mut self, s: impl AsRef<str>) {
        let s = s.as_ref();
        if s.is_empty() {
            self.buf.push('\n');
            return;
        }
        for l in s.lines() {
            self.buf.push_str(&self.unit.repeat(self.level));
            self.buf.push_str(l);
            self.buf.push('\n');
        }
    }

    /// Emit `s` and indent the following lines.
    pub fn open(&mut self, s: impl AsRef<str>) {
        self.line(s);
        self.level += 1;
    }

    /// Dedent, then emit `s`.
    pub fn close(&mut self, s: impl AsRef<str>) {
        self.level = self.level.saturating_sub(1);
        self.line(s);
    }

    pub fn push(&mut self) {
        self.level += 1;
    }

    pub fn pop(&mut self) {
        self.level = self.level.saturating_sub(1);
    }
}
