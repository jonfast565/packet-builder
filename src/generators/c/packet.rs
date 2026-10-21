//! The C declarations (struct and prototypes) and implementation (free,
//! decode and encode functions) of one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::naming::{ident, len_ident, scalar_type};
use crate::generators::common::{Out, StepEmitter, magic_literal, member_category, param_var};
use crate::ir::{Arm, Packet, Union, ValueType};

/// The C name of a union arm's kind constant (`MESSAGEBODY_TEXT`).
pub fn arm_kind(u: &str, arm: &Arm) -> String {
    format!("{}_{}", u.to_ascii_uppercase(), arm.name.to_ascii_uppercase())
}

/// A tagged union: `kind` says which member of `u` is in use.
pub fn emit_union_declaration(out: &mut Out, u: &Union, zero_copy: bool) {
    out.open("enum {");
    for (i, arm) in u.arms.iter().enumerate() {
        out.line(format!("{} = {},", arm_kind(&u.name, arm), i));
    }
    out.close("};");
    out.open(format!("struct {} {{", u.name));
    out.line(format!("int kind; /* {}_* */", u.name.to_ascii_uppercase()));
    out.open("union {");
    let mut members = 0;
    for arm in &u.arms {
        let id = ident(&arm.name);
        match (&arm.ty, arm.is_bytes()) {
            (None, _) => continue,
            (Some(_), true) => out.line(format!("struct {{ {}uint8_t *data; size_t len; }} {};", konst(zero_copy), id)),
            (Some(t), false) => out.line(format!("{} {};", scalar_type(t), id)),
        }
        members += 1;
    }
    if members == 0 {
        out.line("char pb_empty;");
    }
    out.close("} u;");
    out.close("};");
    out.line(format!("void {}_free({} *u);", u.name, u.name));
}

/// `const ` for byte buffers that point into the input (zero-copy).
fn konst(zero_copy: bool) -> &'static str {
    if zero_copy { "const " } else { "" }
}

pub fn emit_union_free(out: &mut Out, u: &Union, zero_copy: bool) {
    out.open(format!("void {}_free({} *u) {{", u.name, u.name));
    out.open("switch (u->kind) {");
    for arm in &u.arms {
        let id = ident(&arm.name);
        match (&arm.ty, arm.is_bytes()) {
            (Some(_), true) if !zero_copy => {
                out.line(format!("case {}: free(u->u.{}.data); break;", arm_kind(&u.name, arm), id));
            }
            (Some(ValueType::Packet(n)), false) => {
                out.line(format!("case {}: {}_free(&u->u.{}); break;", arm_kind(&u.name, arm), n, id));
            }
            _ => {}
        }
    }
    out.line("default: break;");
    out.close("}");
    out.line("memset(u, 0, sizeof *u);");
    out.close("}");
}

pub fn emit_declarations(out: &mut Out, p: &Packet, zero_copy: bool) {
    let name = &p.name;
    out.open(format!("struct {} {{", name));
    if p.members.is_empty() {
        out.line("char pb_empty; /* C requires at least one member */");
    }
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("/* values: {}_* */", cat.to_ascii_uppercase()));
        }
        let id = ident(&m.name);
        let st = scalar_type(&m.ty);
        match (&m.array, &m.ty) {
            (None, ValueType::Mac) => out.line(format!("uint8_t {}[6];", id)),
            (None, ValueType::Str) => {
                out.line(format!("char *{}; /* UTF-8, NUL-terminated */", id));
                out.line(format!("size_t {};", len_ident(p, m)));
            }
            (None, _) => out.line(format!("{} {};", st, id)),
            (Some(_), ValueType::Mac) => {
                out.line(format!("uint8_t (*{})[6];", id));
                out.line(format!("size_t {};", len_ident(p, m)));
            }
            (Some(_), ty) => {
                let k = if ty.is_byte() { konst(zero_copy) } else { "" };
                out.line(format!("{}{} *{};", k, st, id));
                out.line(format!("size_t {};", len_ident(p, m)));
            }
        }
    }
    out.close("};");
    out.line("");
    out.line("/* Decode from the start of data; trailing bytes are ignored. Returns PB_OK or a");
    out.line(format!(" * negative PB_ERR_* code. On success release with {}_free(). */", name));
    let decl = param_decl(p);
    out.line(format!("int {}_decode({} *p, const uint8_t *data, size_t len{});", name, name, decl));
    out.line(format!("int {}_decode_from({} *p, pb_reader *pb_r{});", name, name, decl));
    out.line("/* Encode into a new malloc'ed buffer (*out, *out_len). */");
    out.line(format!("int {}_encode(const {} *p, uint8_t **out, size_t *out_len{});", name, name, decl));
    out.line(format!("int {}_encode_to(const {} *p, pb_writer *pb_w{});", name, name, decl));
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line(format!(
            "/* As protocol version `version` ({}..{}); PB_ERR_CONSTRAINT for another version. */",
            min, latest
        ));
        out.line(format!(
            "int {}_decode_v({} *p, const uint8_t *data, size_t len, unsigned version{});",
            name, name, decl
        ));
        out.line(format!(
            "int {}_encode_v(const {} *p, uint8_t **out, size_t *out_len, unsigned version{});",
            name, name, decl
        ));
    }
    out.line(format!("void {}_free({} *p);", name, name));
    out.line("/* Zero *p, then give members declared `== value` that value. */");
    out.line(format!("void {}_init({} *p);", name, name));
}

/// `, uint8_t pbp_a`: the parameters in signatures.
fn param_decl(p: &Packet) -> String {
    p.params.iter().map(|x| format!(", {} {}", scalar_type(&x.ty), param_var(&x.name))).collect()
}

/// `(void)pbp_a;` for each parameter, which a function may not use.
fn touch_params(out: &mut Out, p: &Packet) {
    for x in &p.params {
        out.line(format!("(void){};", param_var(&x.name)));
    }
}

pub fn emit_implementation(out: &mut Out, p: &Packet, zero_copy: bool) {
    let name = &p.name;
    let decl = param_decl(p);
    let pass: String = p.params.iter().map(|x| format!(", {}", param_var(&x.name))).collect();

    // init
    out.open(format!("void {}_init({} *p) {{", name, name));
    out.line("memset(p, 0, sizeof *p);");
    for m in &p.members {
        match (&m.array, &m.ty, magic_literal(m)) {
            (None, ValueType::Packet(n), _) => out.line(format!("{}_init(&p->{});", n, ident(&m.name))),
            (None, ValueType::Int { signed, .. }, Some(v)) => {
                let v = if *signed { format!("INT64_C({})", v) } else { format!("UINT64_C({})", v) };
                out.line(format!("p->{} = ({}){};", ident(&m.name), scalar_type(&m.ty), v))
            }
            _ => {}
        }
    }
    out.close("}");
    out.line("");

    // free
    out.open(format!("void {}_free({} *p) {{", name, name));
    let mut frees = 0;
    for m in &p.members {
        let id = ident(&m.name);
        match (&m.array, &m.ty) {
            (None, ValueType::Packet(n)) => {
                out.line(format!("{}_free(&p->{});", n, id));
                frees += 1;
            }
            (None, ValueType::Union(n)) => {
                out.line(format!("{}_free(&p->{});", n, id));
                frees += 1;
            }
            (None, ValueType::Str) => {
                out.line(format!("free(p->{});", id));
                out.line(format!("p->{} = NULL;", id));
                out.line(format!("p->{} = 0;", len_ident(p, m)));
                frees += 1;
            }
            (Some(_), ty) => {
                let len = len_ident(p, m);
                if let ValueType::Packet(n) = ty {
                    out.open(format!("if (p->{}) {{", id));
                    out.line("size_t pb_i;");
                    out.line(format!("for (pb_i = 0; pb_i < p->{}; pb_i++) {}_free(&p->{}[pb_i]);", len, n, id));
                    out.close("}");
                }
                // Zero-copy byte buffers belong to the input.
                if !(zero_copy && ty.is_byte()) {
                    out.line(format!("free(p->{});", id));
                }
                out.line(format!("p->{} = NULL;", id));
                out.line(format!("p->{} = 0;", len));
                frees += 1;
            }
            _ => {}
        }
    }
    if frees == 0 {
        out.line("(void)p;");
    }
    out.close("}");
    out.line("");

    // decode
    out.open(format!("int {}_decode({} *p, const uint8_t *data, size_t len{}) {{", name, name, decl));
    out.line("pb_reader pb_r;");
    out.line("pb_reader_init(&pb_r, data, len);");
    out.line(format!("return {}_decode_from(p, &pb_r{});", name, pass));
    out.close("}");
    out.line("");
    let versions = p.versions.map(|_| p.version_bounds());
    if let Some((min, latest)) = versions {
        out.open(format!(
            "int {}_decode_v({} *p, const uint8_t *data, size_t len, unsigned version{}) {{",
            name, name, decl
        ));
        out.line("pb_reader pb_r;");
        out.line("pb_reader_init(&pb_r, data, len);");
        out.line("memset(p, 0, sizeof *p);");
        out.line(format!(
            "if (pb_set_version(&pb_r.tr, version, {}, {}) != PB_OK) return PB_ERR_CONSTRAINT;",
            min, latest
        ));
        out.line(format!("return {}_decode_from(p, &pb_r{});", name, pass));
        out.close("}");
        out.line("");
    }

    let mut body = Out::new("    ");
    body.push();
    Decoder::new(p, zero_copy).emit_steps(&mut body);
    out.open(format!("int {}_decode_from({} *p, pb_reader *pb_r{}) {{", name, name, decl));
    out.line("int pb_rc = PB_OK;");
    out.line("uint64_t pb_u = 0;");
    out.line("memset(p, 0, sizeof *p);");
    out.line(format!("PB_TRY(pb_enter(&pb_r->tr, \"{}\"));", name));
    if p.needs_start(false) {
        out.line("size_t pb_start = pb_reader_position(pb_r);");
    }
    out.line("(void)pb_u;");
    out.line("(void)pb_r;");
    touch_params(out, p);
    out.pop();
    out.buf.push_str(&body.buf);
    out.push();
    out.line("pb_leave(&pb_r->tr);");
    out.line("return PB_OK;");
    out.pop();
    out.line("pb_fail:");
    out.push();
    out.line("pb_rfail(pb_r, pb_rc);");
    out.line(format!("{}_free(p);", name));
    out.line("return pb_rc;");
    out.close("}");
    out.line("");

    // encode
    out.open(format!("int {}_encode(const {} *p, uint8_t **out, size_t *out_len{}) {{", name, name, decl));
    out.line("pb_writer pb_w;");
    out.line("int rc;");
    out.line("pb_writer_init(&pb_w);");
    out.line(format!("rc = {}_encode_to(p, &pb_w{});", name, pass));
    out.line("if (rc == PB_OK) rc = pb_writer_finish(&pb_w);");
    out.open("if (rc != PB_OK) {");
    out.line("pb_writer_free(&pb_w);");
    out.line("return rc;");
    out.close("}");
    out.line("*out = pb_w.buf ? pb_w.buf : (uint8_t *)malloc(1);");
    out.line("*out_len = pb_w.len;");
    out.line("return *out ? PB_OK : PB_ERR_NOMEM;");
    out.close("}");
    out.line("");
    if let Some((min, latest)) = versions {
        out.open(format!(
            "int {}_encode_v(const {} *p, uint8_t **out, size_t *out_len, unsigned version{}) {{",
            name, name, decl
        ));
        out.line("pb_writer pb_w;");
        out.line("int rc;");
        out.line("pb_writer_init(&pb_w);");
        out.line(format!(
            "if (pb_set_version(&pb_w.tr, version, {}, {}) != PB_OK) return PB_ERR_CONSTRAINT;",
            min, latest
        ));
        out.line(format!("rc = {}_encode_to(p, &pb_w{});", name, pass));
        out.line("if (rc == PB_OK) rc = pb_writer_finish(&pb_w);");
        out.open("if (rc != PB_OK) {");
        out.line("pb_writer_free(&pb_w);");
        out.line("return rc;");
        out.close("}");
        out.line("*out = pb_w.buf ? pb_w.buf : (uint8_t *)malloc(1);");
        out.line("*out_len = pb_w.len;");
        out.line("return *out ? PB_OK : PB_ERR_NOMEM;");
        out.close("}");
        out.line("");
    }

    out.open(format!("int {}_encode_to(const {} *p, pb_writer *pb_w{}) {{", name, name, decl));
    let encoder = Encoder::new(p);
    encoder.emit_locals(out);
    out.line("(void)p;");
    out.line("(void)pb_w;");
    touch_params(out, p);
    if p.needs_start(true) {
        out.line("size_t pb_start = pb_writer_position(pb_w);");
    }
    out.line(format!("PB_CHECK(pb_enter(&pb_w->tr, \"{}\"));", name));
    encoder.emit_steps(out);
    out.line("pb_leave(&pb_w->tr);");
    out.line("return PB_OK;");
    out.close("}");
}
