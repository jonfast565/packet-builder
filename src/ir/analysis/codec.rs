//! Choosing how each field travels on the wire ([`Codec`]).

use super::context::Ctx;
use super::cursor::Align;
use super::types::type_label;
use crate::errors::Diagnostic;
use crate::ir::model::{Codec, StrMode};
use crate::models::parsing_models::{Endianness, Span, TypeExpr, TypeNode};

impl<'a> Ctx<'a> {
    pub fn codec_for(
        &mut self,
        t: &TypeNode,
        field_endian: Option<Endianness>,
        default_endian: &Endianness,
        align: Align,
        span: Span,
        name: &str,
    ) -> Codec {
        let explicit = field_endian.is_some();
        let endian = field_endian.unwrap_or_else(|| default_endian.clone());
        let aligned = align.is_aligned();
        let misaligned = |ctx: &mut Ctx, what: &str| {
            let at = align.describe();
            ctx.diags.push(
                Diagnostic::new(
                    format!("{} `{}` starts {}; {} must be byte aligned", type_label(t), name, at, what),
                    span,
                )
                .with_note(
                    "use a uN type for integers that live in the bit stream, or add `_ uN` padding before this field",
                ),
            );
        };
        match t {
            TypeNode::Packet(n) => {
                if !aligned {
                    misaligned(self, "nested packets");
                }
                Codec::Packet(n.clone())
            }
            TypeNode::Float32 | TypeNode::Float64 => {
                if !aligned {
                    misaligned(self, "floating point fields");
                }
                Codec::Float { width: t.bit_width().unwrap(), endian }
            }
            TypeNode::MacAddress => {
                if !aligned {
                    misaligned(self, "mac addresses");
                }
                Codec::Mac
            }
            TypeNode::Str | TypeNode::CStr | TypeNode::PrefixedStr { .. } => {
                // Strings go through string_codec; reaching here means a
                // string type was used where only integers are allowed.
                self.diags.push(Diagnostic::new(format!("`{}` cannot have a string type here", name), span));
                Codec::Bytes { nbytes: 1, endian }
            }
            TypeNode::Bits { width, .. } => {
                if aligned && width % 8 == 0 {
                    Codec::Bytes { nbytes: width / 8, endian }
                } else {
                    if explicit && *width > 8 {
                        self.diags.push(
                            Diagnostic::new(
                                format!(
                                    "`{}` is not a whole number of aligned bytes, so it cannot have a byte order",
                                    name
                                ),
                                span,
                            )
                            .with_note("bit-stream integers are always read most significant bit first"),
                        );
                    }
                    Codec::Bits { width: *width }
                }
            }
            other => {
                let width = other.bit_width().unwrap();
                if !aligned {
                    misaligned(self, "standard integer types");
                }
                Codec::Bytes { nbytes: width / 8, endian }
            }
        }
    }

    pub fn string_codec(&mut self, f: &TypeExpr, default_endian: &Endianness, align: Align) -> Codec {
        if !align.is_aligned() {
            self.diags.push(
                Diagnostic::new(
                    format!("string `{}` starts {}; strings must be byte aligned", f.id, align.describe()),
                    f.span,
                )
                .with_note("add `_ uN` padding or `align 1` before this field"),
            );
        }
        if f.endianness.is_some() && !matches!(f.expr, TypeNode::PrefixedStr { .. }) {
            self.diags.push(Diagnostic::new(format!("string `{}` cannot have a byte order", f.id), f.span));
        }
        match &f.expr {
            TypeNode::Char => Codec::Str(StrMode::Padded),
            TypeNode::Str => Codec::Str(StrMode::Exact),
            TypeNode::CStr | TypeNode::PrefixedStr { .. } if f.array.is_some() => {
                self.diags.push(
                    Diagnostic::new(
                        format!("`{}` already determines its own length and cannot take [..]", f.id),
                        f.span,
                    )
                    .with_note("use char[n] or string[n] for strings whose length comes from elsewhere"),
                );
                Codec::Str(StrMode::CString)
            }
            TypeNode::CStr => Codec::Str(StrMode::CString),
            TypeNode::PrefixedStr { prefix, endianness } => {
                let width = match prefix.integer_info() {
                    Some((w, false)) if !matches!(**prefix, TypeNode::Bytes | TypeNode::Char) => w,
                    _ => {
                        self.diags.push(Diagnostic::new(
                            format!("the length prefix of `{}` must be an unsigned integer type", f.id),
                            f.span,
                        ));
                        8
                    }
                };
                let codec = self.codec_for(prefix, endianness.clone(), default_endian, align, f.span, &f.id);
                Codec::Str(StrMode::Prefixed { prefix: Box::new(codec), width })
            }
            _ => Codec::Str(StrMode::Exact),
        }
    }
}
