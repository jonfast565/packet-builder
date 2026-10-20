//! Decoded values.

use std::fmt::Write as _;

use crate::ir::{Member, Module, Packet, ValueType};

/// A decoded member. Integers keep their exact value (up to 64 bits, signed
/// or unsigned); byte arrays and MAC addresses are `Bytes`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i128),
    Float(f64),
    Bytes(Vec<u8>),
    Str(String),
    List(Vec<Value>),
    Struct(Struct),
}

/// A decoded packet: its members in declaration order.
#[derive(Debug, Clone, PartialEq)]
pub struct Struct {
    pub packet: String,
    pub fields: Vec<(String, Value)>,
}

impl Struct {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.fields.iter_mut().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

impl Value {
    /// The zero value of a member (what generated structs start with).
    pub fn default_for(module: &Module, m: &Member) -> Value {
        match (&m.array, &m.ty) {
            (Some(_), ty) if ty.is_byte() => Value::Bytes(Vec::new()),
            (Some(_), _) => Value::List(Vec::new()),
            (None, ty) => Value::default_scalar(module, ty),
        }
    }

    pub fn default_scalar(module: &Module, ty: &ValueType) -> Value {
        match ty {
            ValueType::Int { .. } => Value::Int(0),
            ValueType::Float { .. } => Value::Float(0.0),
            ValueType::Mac => Value::Bytes(vec![0; 6]),
            ValueType::Str => Value::Str(String::new()),
            ValueType::Packet(n) => match module.packets.iter().find(|p| &p.name == n) {
                Some(p) => Value::Struct(Struct::default_for(module, p)),
                None => Value::Int(0),
            },
        }
    }

    /// JSON text: integers and floats as numbers, byte buffers as hex
    /// strings, packets as objects.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out, None);
        out
    }

    /// Indented JSON, `indent` spaces per level.
    pub fn to_json_pretty(&self, indent: usize) -> String {
        let mut out = String::new();
        self.write_json(&mut out, Some((indent, 0)));
        out
    }

    fn write_json(&self, out: &mut String, pretty: Option<(usize, usize)>) {
        let nl = |out: &mut String, level: usize| {
            if let Some((step, _)) = pretty {
                out.push('\n');
                out.push_str(&" ".repeat(step * level));
            }
        };
        let level = pretty.map(|(_, l)| l).unwrap_or(0);
        let inner = pretty.map(|(s, l)| (s, l + 1));
        match self {
            Value::Int(v) => {
                let _ = write!(out, "{}", v);
            }
            Value::Float(v) if v.is_finite() => {
                let _ = write!(out, "{:?}", v);
            }
            Value::Float(_) => out.push_str("null"),
            Value::Bytes(b) => {
                out.push('"');
                for x in b {
                    let _ = write!(out, "{:02x}", x);
                }
                out.push('"');
            }
            Value::Str(s) => json_string(out, s),
            Value::List(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, level + 1);
                    v.write_json(out, inner);
                }
                if !items.is_empty() {
                    nl(out, level);
                }
                out.push(']');
            }
            Value::Struct(s) => {
                out.push('{');
                for (i, (k, v)) in s.fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, level + 1);
                    json_string(out, k);
                    out.push(':');
                    if pretty.is_some() {
                        out.push(' ');
                    }
                    v.write_json(out, inner);
                }
                if !s.fields.is_empty() {
                    nl(out, level);
                }
                out.push('}');
            }
        }
    }
}

impl Struct {
    pub fn default_for(module: &Module, p: &Packet) -> Struct {
        Struct {
            packet: p.name.clone(),
            fields: p.members.iter().map(|m| (m.name.clone(), Value::default_for(module, m))).collect(),
        }
    }
}

fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
