//! The C declarations (struct and prototypes) and implementation (free,
//! decode and encode functions) of one packet.

use super::decode::Decoder;
use super::encode::Encoder;
use super::expr::store_value;
use super::naming::{ident, len_ident, scalar_type};
use crate::generators::common::{Out, StepEmitter, member_category};
use crate::ir::{Packet, ValueType};

pub fn emit_declarations(out: &mut Out, p: &Packet) {
    let name = &p.name;
    out.open(format!("typedef struct {} {{", name));
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
            (Some(_), _) => {
                out.line(format!("{} *{};", st, id));
                out.line(format!("size_t {};", len_ident(p, m)));
            }
        }
    }
    out.close(format!("}} {};", name));
    out.line("");
    out.line("/* Decode from the start of data; trailing bytes are ignored. Returns PB_OK or a");
    out.line(format!(" * negative PB_ERR_* code. On success release with {}_free(). */", name));
    out.line(format!("int {}_decode({} *p, const uint8_t *data, size_t len);", name, name));
    out.line(format!("int {}_decode_from({} *p, pb_reader *pb_r);", name, name));
    out.line("/* Encode into a new malloc'ed buffer (*out, *out_len). */");
    out.line(format!("int {}_encode(const {} *p, uint8_t **out, size_t *out_len);", name, name));
    out.line(format!("int {}_encode_to(const {} *p, pb_writer *pb_w);", name, name));
    out.line(format!("void {}_free({} *p);", name, name));
}

pub fn emit_implementation(out: &mut Out, p: &Packet) {
    let name = &p.name;

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
                out.line(format!("free(p->{});", id));
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
    out.open(format!("int {}_decode({} *p, const uint8_t *data, size_t len) {{", name, name));
    out.line("pb_reader pb_r;");
    out.line("pb_reader_init(&pb_r, data, len);");
    out.line(format!("return {}_decode_from(p, &pb_r);", name));
    out.close("}");
    out.line("");

    let mut body = Out::new("    ");
    body.push();
    Decoder::new(p).emit_steps(&mut body);
    out.open(format!("int {}_decode_from({} *p, pb_reader *pb_r) {{", name, name));
    let uses_try = body.buf.contains("PB_TRY");
    if uses_try {
        out.line("int pb_rc = PB_OK;");
    }
    out.line("uint64_t pb_u = 0;");
    out.line("memset(p, 0, sizeof *p);");
    if p.uses_align() {
        out.line("size_t pb_start = pb_reader_position(pb_r);");
    }
    out.line("(void)pb_u;");
    out.line("(void)pb_r;");
    out.pop();
    out.buf.push_str(&body.buf);
    out.push();
    out.line("return PB_OK;");
    if uses_try {
        out.pop();
        out.line("pb_fail:");
        out.push();
        out.line(format!("{}_free(p);", name));
        out.line("return pb_rc;");
    }
    out.close("}");
    out.line("");

    // encode
    out.open(format!("int {}_encode(const {} *p, uint8_t **out, size_t *out_len) {{", name, name));
    out.line("pb_writer pb_w;");
    out.line("int rc;");
    out.line("pb_writer_init(&pb_w);");
    out.line(format!("rc = {}_encode_to(p, &pb_w);", name));
    out.open("if (rc != PB_OK) {");
    out.line("pb_writer_free(&pb_w);");
    out.line("return rc;");
    out.close("}");
    out.line("*out = pb_w.buf ? pb_w.buf : (uint8_t *)malloc(1);");
    out.line("*out_len = pb_w.len;");
    out.line("return *out ? PB_OK : PB_ERR_NOMEM;");
    out.close("}");
    out.line("");

    out.open(format!("int {}_encode_to(const {} *p, pb_writer *pb_w) {{", name, name));
    let encoder = Encoder::new(p);
    for (m, e) in p.encode_calc_members() {
        out.line(format!("{} pbc_{} = {};", scalar_type(&m.ty), m.name, store_value(encoder.scope.expr(e), &m.ty)));
    }
    out.line("(void)p;");
    out.line("(void)pb_w;");
    if p.uses_align() {
        out.line("size_t pb_start = pb_writer_position(pb_w);");
    }
    encoder.emit_steps(out);
    out.line("return PB_OK;");
    out.close("}");
}
