/* ---- packet-builder runtime: implementation ------------------------------ */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PB_RUNTIME_IMPLEMENTED
#define PB_RUNTIME_IMPLEMENTED

#if defined(__GNUC__) || defined(__clang__)
#define PB_FN static __attribute__((unused))
#else
#define PB_FN static
#endif

/* In generated decoders: on failure jump to pb_fail, which records the error. */
#define PB_TRY(e) do { pb_rc = (e); if (pb_rc != PB_OK) goto pb_fail; } while (0)
/* In generated encoders: on failure record the error and return its code. */
#define PB_CHECK(e) do { int pb_rc_ = (e); if (pb_rc_ != PB_OK) return pb_note(&pb_w->tr, &pb_w->err, pb_rc_, pb_w->pos, 0); } while (0)
/* Inside the runtime: pass errors up. */
#define PB_PASS(e) do { int pb_rc_ = (e); if (pb_rc_ != PB_OK) return pb_rc_; } while (0)

const char *pb_strerror(int rc) {
    switch (rc) {
    case PB_OK: return "ok";
    case PB_ERR_INCOMPLETE: return "unexpected end of data";
    case PB_ERR_INVALID: return "invalid data";
    case PB_ERR_RANGE: return "value out of range";
    case PB_ERR_NOMEM: return "out of memory";
    case PB_ERR_TEXT: return "invalid string";
    case PB_ERR_MISMATCH: return "value does not match the data";
    case PB_ERR_CONSTRAINT: return "constraint violated";
    default: return "unknown error";
    }
}

/* Record the first error with the trace depth at which it happened. */
PB_FN int pb_note(const pb_trace *t, pb_error *e, int code, size_t pos, size_t needed_bits) {
    if (e->code == PB_OK) {
        e->code = code;
        e->bit_offset = pos;
        e->needed_bits = code == PB_ERR_INCOMPLETE ? needed_bits : 0;
        e->depth = t->depth;
    }
    return code;
}

PB_FN int pb_enter(pb_trace *t, const char *packet) {
    if (t->depth >= PB_MAX_DEPTH) return PB_ERR_INVALID;
    t->frames[t->depth].packet = packet;
    t->frames[t->depth].field = "";
    t->frames[t->depth].index = -1;
    t->depth++;
    return PB_OK;
}

PB_FN void pb_leave(pb_trace *t) {
    if (t->depth) t->depth--;
}

PB_FN void pb_at(pb_trace *t, const char *field) {
    t->frames[t->depth - 1].field = field;
    t->frames[t->depth - 1].index = -1;
}

PB_FN void pb_at_index(pb_trace *t, size_t index) { t->frames[t->depth - 1].index = (long)index; }

static void pb_append(char *buf, size_t n, size_t *at, const char *s) {
    while (*s && *at + 1 < n) buf[(*at)++] = *s++;
    buf[*at] = 0;
}

static char *pb_path(const pb_trace *t, const pb_error *e, char *buf, size_t n) {
    size_t at = 0;
    unsigned i;
    char num[32];
    if (!n) return buf;
    buf[0] = 0;
    if (e->depth) pb_append(buf, n, &at, t->frames[0].packet);
    for (i = 0; i < e->depth && t->frames[i].field[0]; i++) {
        pb_append(buf, n, &at, ".");
        pb_append(buf, n, &at, t->frames[i].field);
        if (t->frames[i].index >= 0) {
            snprintf(num, sizeof num, "[%ld]", t->frames[i].index);
            pb_append(buf, n, &at, num);
        }
    }
    return buf;
}

static char *pb_describe(const pb_trace *t, const pb_error *e, char *buf, size_t n) {
    size_t at;
    char num[48];
    pb_path(t, e, buf, n);
    at = strlen(buf);
    if (at) pb_append(buf, n, &at, ": ");
    pb_append(buf, n, &at, pb_strerror(e->code));
    snprintf(num, sizeof num, " (at bit %lu)", (unsigned long)e->bit_offset);
    pb_append(buf, n, &at, num);
    return buf;
}

char *pb_reader_path(const pb_reader *r, char *buf, size_t n) { return pb_path(&r->tr, &r->err, buf, n); }

char *pb_writer_path(const pb_writer *w, char *buf, size_t n) { return pb_path(&w->tr, &w->err, buf, n); }

char *pb_reader_describe(const pb_reader *r, char *buf, size_t n) { return pb_describe(&r->tr, &r->err, buf, n); }

char *pb_writer_describe(const pb_writer *w, char *buf, size_t n) { return pb_describe(&w->tr, &w->err, buf, n); }

void pb_reader_init(pb_reader *r, const uint8_t *data, size_t len) {
    memset(r, 0, sizeof *r);
    r->data = data;
    r->len = len;
    r->limit = len * 8;
}

/* Record a failed decode (called at pb_fail). */
PB_FN int pb_rfail(pb_reader *r, int code) {
    return pb_note(&r->tr, &r->err, code, r->pos, r->short_bits);
}

PB_FN size_t pb_remaining_bits(const pb_reader *r) { return r->limit - r->pos; }
/* Whole bytes left before the end of the window or input (`remaining`). */
PB_FN int64_t pb_remaining_bytes(const pb_reader *r) { return (int64_t)(pb_remaining_bits(r) / 8); }

// @versions{
/* The protocol version (`version`) of a reader or writer (its trace), or
 * `latest` while none is set. */
PB_FN int64_t pb_version_or(const pb_trace *t, unsigned latest) { return (int64_t)(t->version ? t->version : latest); }

/* Code as protocol version v, which must be in min..latest. */
PB_FN int pb_set_version(pb_trace *t, int64_t v, unsigned min, unsigned latest) {
    if (v < (int64_t)min || v > (int64_t)latest) return PB_ERR_CONSTRAINT;
    t->version = (unsigned)v;
    return PB_OK;
}

/* The version a value carries in-band: used unless one is set already. */
PB_FN int pb_adopt_version(pb_trace *t, int64_t v, unsigned min, unsigned latest) {
    return t->version ? PB_OK : pb_set_version(t, v, min, latest);
}
// @versions}

/* `bits` more bits are needed: incomplete input at the top level, invalid
 * data inside a window. */
PB_FN int pb_short(pb_reader *r, size_t bits) {
    r->short_bits = bits - pb_remaining_bits(r);
    return r->windows == 0 ? PB_ERR_INCOMPLETE : PB_ERR_INVALID;
}

/* Read from `offset` bytes after bit `from` (the packet start, or 0 for the
 * start of the input) until pb_jump_back; windows do not apply there. */
PB_FN int pb_jump_to(pb_reader *r, size_t from, int64_t offset, pb_jump *saved) {
    if (offset < 0 || from % 8 || (uint64_t)offset > r->len || from + (size_t)offset * 8 > r->len * 8) {
        return PB_ERR_INVALID;
    }
    saved->pos = r->pos;
    saved->limit = r->limit;
    saved->windows = r->windows;
    r->pos = from + (size_t)offset * 8;
    r->limit = r->len * 8;
    r->windows = 0;
    return PB_OK;
}

PB_FN void pb_jump_back(pb_reader *r, const pb_jump *saved) {
    r->pos = saved->pos;
    r->limit = saved->limit;
    r->windows = saved->windows;
}

#define PB_NEED(r, bits) do { if ((bits) > pb_remaining_bits(r)) return pb_short((r), (bits)); } while (0)

/* Restrict reading to the next `bytes` bytes; *saved receives the previous
 * limit for pb_pop_limit. */
PB_FN int pb_push_limit(pb_reader *r, int64_t bytes, size_t *saved) {
    if (bytes < 0) return PB_ERR_INVALID;
    if ((uint64_t)bytes > pb_remaining_bits(r) / 8) return pb_short(r, (size_t)bytes * 8);
    *saved = r->limit;
    r->limit = r->pos + (size_t)bytes * 8;
    r->windows++;
    return PB_OK;
}

/* Skip what is left of the current window and restore `saved`; with
 * `exact`, bytes left over are an error. */
PB_FN int pb_pop_limit(pb_reader *r, size_t saved, int exact) {
    if (exact && pb_remaining_bits(r) > 0) return PB_ERR_INVALID;
    r->pos = r->limit;
    r->limit = saved;
    r->windows--;
    return PB_OK;
}

PB_FN int pb_read_bits(pb_reader *r, unsigned width, uint64_t *out) {
    uint64_t v = 0;
    unsigned left = width;
    PB_NEED(r, width);
    while (left > 0) {
        unsigned off = (unsigned)(r->pos & 7);
        unsigned take = 8 - off < left ? 8 - off : left;
        unsigned bits = ((unsigned)r->data[r->pos >> 3] >> (8 - off - take)) & ((1u << take) - 1u);
        v = (v << take) | bits;
        r->pos += take;
        left -= take;
    }
    *out = v;
    return PB_OK;
}

PB_FN int pb_read_uint(pb_reader *r, unsigned nbytes, int little, uint64_t *out) {
    uint64_t v = 0;
    size_t start = r->pos >> 3;
    unsigned i;
    PB_NEED(r, (size_t)nbytes * 8);
    for (i = 0; i < nbytes; i++) {
        uint8_t b = little ? r->data[start + nbytes - 1 - i] : r->data[start + i];
        v = (v << 8) | b;
    }
    r->pos += (size_t)nbytes * 8;
    *out = v;
    return PB_OK;
}

PB_FN int pb_read_bytes(pb_reader *r, uint8_t *dst, size_t n) {
    if (n > pb_remaining_bits(r) / 8) return pb_short(r, n * 8);
    if (n) memcpy(dst, r->data + (r->pos >> 3), n);
    r->pos += n * 8;
    return PB_OK;
}

/* The next n bytes as a pointer into the input (zero-copy). */
PB_FN int pb_read_ref(pb_reader *r, size_t n, const uint8_t **out) {
    if (n > pb_remaining_bits(r) / 8) return pb_short(r, n * 8);
    *out = r->data + (r->pos >> 3);
    r->pos += n * 8;
    return PB_OK;
}

PB_FN int pb_skip_bits(pb_reader *r, size_t bits) {
    PB_NEED(r, bits);
    r->pos += bits;
    return PB_OK;
}

PB_FN size_t pb_reader_position(const pb_reader *r) { return r->pos; }
PB_FN size_t pb_writer_position(const pb_writer *w) { return w->pos; }

/* Padding needed after `offset` bits to reach a multiple of `unit` bits. */
PB_FN size_t pb_pad(size_t offset, size_t unit) { return (unit - offset % unit) % unit; }

/* Strict UTF-8 validation (no overlong forms, surrogates or values > U+10FFFF). */
PB_FN int pb_utf8_valid(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        size_t len, k;
        uint32_t cp;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xC2 && c <= 0xDF) { len = 2; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07; }
        else return 0;
        if (i + len > n) return 0;
        for (k = 1; k < len; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if ((len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
            return 0;
        i += len;
    }
    return 1;
}

/* Copy n bytes into a new NUL-terminated string (cut at the first NUL when
 * until_nul is set) and validate it as UTF-8. */
PB_FN int pb_text(const uint8_t *src, size_t n, int until_nul, char **out, size_t *out_len) {
    char *s;
    if (until_nul) {
        const uint8_t *nul = n ? (const uint8_t *)memchr(src, 0, n) : NULL;
        if (nul) n = (size_t)(nul - src);
    }
    if (!pb_utf8_valid(src, n)) return PB_ERR_TEXT;
    s = (char *)malloc(n + 1);
    if (!s) return PB_ERR_NOMEM;
    if (n) memcpy(s, src, n);
    s[n] = 0;
    *out = s;
    *out_len = n;
    return PB_OK;
}

PB_FN int pb_read_text(pb_reader *r, size_t n, int until_nul, char **out, size_t *out_len) {
    int rc;
    if (n > pb_remaining_bits(r) / 8) return pb_short(r, n * 8);
    rc = pb_text(r->data + (r->pos >> 3), n, until_nul, out, out_len);
    if (rc == PB_OK) r->pos += n * 8;
    return rc;
}

/* A NUL-terminated string; the terminator is consumed. */
PB_FN int pb_read_ctext(pb_reader *r, char **out, size_t *out_len) {
    size_t start = r->pos >> 3;
    size_t end = r->limit >> 3;
    const uint8_t *nul = start < end ? (const uint8_t *)memchr(r->data + start, 0, end - start) : NULL;
    size_t n;
    int rc;
    if (!nul) return pb_short(r, pb_remaining_bits(r) + 8);
    n = (size_t)(nul - (r->data + start));
    rc = pb_text(r->data + start, n, 0, out, out_len);
    if (rc == PB_OK) r->pos += (n + 1) * 8;
    return rc;
}

/* One variable-length integer (kind: 0 uleb128, 1 sleb128, 2 zigzag, 3 vlq,
 * 4 quic, 5 varint15); signed kinds give the two's complement bits. */
PB_FN int pb_read_varint(pb_reader *r, unsigned kind, uint64_t *out) {
    uint64_t v = 0, b;
    unsigned shift = 0;
    if (kind == 5) {
        PB_PASS(pb_read_uint(r, 1, 0, &b));
        if (b & 0x80) {
            PB_PASS(pb_read_uint(r, 1, 0, &v));
            v |= (b & 0x7f) << 8;
        } else {
            v = b;
        }
        *out = v;
        return PB_OK;
    }
    if (kind == 4) {
        unsigned n;
        PB_PASS(pb_read_uint(r, 1, 0, &b));
        n = 1u << (b >> 6);
        v = b & 0x3f;
        if (n > 1) {
            uint64_t rest;
            PB_PASS(pb_read_uint(r, n - 1, 0, &rest));
            v = (v << (8 * (n - 1))) | rest;
        }
        *out = v;
        return PB_OK;
    }
    for (;;) {
        PB_PASS(pb_read_uint(r, 1, 0, &b));
        if (kind == 3) {
            if (v >> 57) return PB_ERR_INVALID;
            v = (v << 7) | (b & 0x7f);
        } else {
            /* The 10th byte holds bit 63 only (and, for sleb128, its sign). */
            int last_ok = kind == 1 ? ((b & 0x7f) == 0 || (b & 0x7f) == 0x7f) : (b & 0x7e) == 0;
            if (shift >= 64 || (shift == 63 && ((b & 0x80) || !last_ok))) return PB_ERR_INVALID;
            v |= (b & 0x7f) << shift;
        }
        shift += 7;
        if (!(b & 0x80)) {
            if (kind == 1 && shift < 64 && (b & 0x40)) v |= ~(uint64_t)0 << shift;
            break;
        }
    }
    if (kind == 2) v = (v >> 1) ^ (0 - (v & 1));
    *out = v;
    return PB_OK;
}

/* Bytes up to `term` (consumed) into a new allocation. Without it: the rest
 * of the input when `optional`, otherwise an error. */
/* pb_read_until without copying: *out points into the input (zero-copy). */
PB_FN int pb_read_until_ref(pb_reader *r, const uint8_t *term, size_t tlen, int optional, const uint8_t **out, size_t *out_len) {
    size_t start = r->pos >> 3, end = r->limit >> 3, i, n = 0;
    int found = 0;
    for (i = start; i + tlen <= end; i++) {
        if (memcmp(r->data + i, term, tlen) == 0) {
            found = 1;
            n = i - start;
            break;
        }
    }
    if (!found) {
        if (!optional) return pb_short(r, pb_remaining_bits(r) + 8);
        n = end - start;
    }
    *out = r->data + start;
    *out_len = n;
    r->pos = (start + n + (found ? tlen : 0)) * 8;
    return PB_OK;
}

PB_FN int pb_read_until(pb_reader *r, const uint8_t *term, size_t tlen, int optional, uint8_t **out, size_t *out_len) {
    const uint8_t *ref;
    PB_PASS(pb_read_until_ref(r, term, tlen, optional, &ref, out_len));
    *out = (uint8_t *)malloc(*out_len ? *out_len : 1);
    if (!*out) return PB_ERR_NOMEM;
    if (*out_len) memcpy(*out, ref, *out_len);
    return PB_OK;
}

/* Append code point `cp` to a UTF-8 buffer. */
static size_t pb_put_utf8(uint8_t *o, uint32_t cp) {
    if (cp < 0x80) { o[0] = (uint8_t)cp; return 1; }
    if (cp < 0x800) { o[0] = (uint8_t)(0xC0 | (cp >> 6)); o[1] = (uint8_t)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        o[0] = (uint8_t)(0xE0 | (cp >> 12)); o[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)); o[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    }
    o[0] = (uint8_t)(0xF0 | (cp >> 18)); o[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

/* Text in encoding `enc` (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
 * 4 UTF-16BE) as a new NUL-terminated UTF-8 string; with `padded`, the text
 * ends at the first NUL character. */
PB_FN int pb_convert_text(const uint8_t *src, size_t n, unsigned enc, int padded, char **out, size_t *out_len) {
    uint8_t *o;
    size_t i, k = 0;
    if (enc <= 2) {
        if (padded) {
            const uint8_t *nul = n ? (const uint8_t *)memchr(src, 0, n) : NULL;
            if (nul) n = (size_t)(nul - src);
        }
        if (enc == 0) return pb_text(src, n, 0, out, out_len);
        o = (uint8_t *)malloc(n * 2 + 1);
        if (!o) return PB_ERR_NOMEM;
        for (i = 0; i < n; i++) {
            if (enc == 1 && src[i] >= 0x80) { free(o); return PB_ERR_TEXT; }
            k += pb_put_utf8(o + k, src[i]);
        }
    } else {
        if (n % 2) return PB_ERR_TEXT;
        o = (uint8_t *)malloc(n * 2 + 1);
        if (!o) return PB_ERR_NOMEM;
        for (i = 0; i + 1 < n; i += 2) {
            uint32_t u = enc == 3 ? (uint32_t)(src[i] | (src[i + 1] << 8)) : (uint32_t)((src[i] << 8) | src[i + 1]);
            if (u == 0 && padded) break;
            if (u >= 0xD800 && u <= 0xDBFF) {
                uint32_t lo;
                if (i + 3 >= n) { free(o); return PB_ERR_TEXT; }
                lo = enc == 3 ? (uint32_t)(src[i + 2] | (src[i + 3] << 8)) : (uint32_t)((src[i + 2] << 8) | src[i + 3]);
                if (lo < 0xDC00 || lo > 0xDFFF) { free(o); return PB_ERR_TEXT; }
                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else if (u >= 0xDC00 && u <= 0xDFFF) {
                free(o);
                return PB_ERR_TEXT;
            }
            k += pb_put_utf8(o + k, u);
        }
    }
    o[k] = 0;
    *out = (char *)o;
    *out_len = k;
    return PB_OK;
}

/* n bytes of text in encoding `enc` (see pb_convert_text). */
PB_FN int pb_read_text_enc(pb_reader *r, size_t n, int padded, unsigned enc, char **out, size_t *out_len) {
    int rc;
    if (n > pb_remaining_bits(r) / 8) return pb_short(r, n * 8);
    rc = pb_convert_text(r->data + (r->pos >> 3), n, enc, padded, out, out_len);
    if (rc == PB_OK) r->pos += n * 8;
    return rc;
}

/* Text up to `term` in encoding `enc`. */
PB_FN int pb_read_text_until(pb_reader *r, const uint8_t *term, size_t tlen, int optional, unsigned enc, char **out, size_t *out_len) {
    uint8_t *raw;
    size_t n;
    int rc = pb_read_until(r, term, tlen, optional, &raw, &n);
    if (rc != PB_OK) return rc;
    rc = pb_convert_text(raw, n, enc, 0, out, out_len);
    free(raw);
    return rc;
}

/* A growable text buffer for the *_to_json functions. */
typedef struct pb_sb {
    char *buf;
    size_t len, cap;
    int failed;
} pb_sb;

PB_FN void pb_sb_put(pb_sb *b, const char *s, size_t n) {
    if (b->failed) return;
    if (b->len + n + 1 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 128;
        char *nb;
        while (ncap < b->len + n + 1) ncap *= 2;
        nb = (char *)realloc(b->buf, ncap);
        if (!nb) {
            b->failed = 1;
            return;
        }
        b->buf = nb;
        b->cap = ncap;
    }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = 0;
}

PB_FN void pb_sb_puts(pb_sb *b, const char *s) { pb_sb_put(b, s, strlen(s)); }

PB_FN void pb_sb_i64(pb_sb *b, int64_t v) {
    char t[32];
    snprintf(t, sizeof t, "%lld", (long long)v);
    pb_sb_puts(b, t);
}

PB_FN void pb_sb_u64(pb_sb *b, uint64_t v) {
    char t[32];
    snprintf(t, sizeof t, "%llu", (unsigned long long)v);
    pb_sb_puts(b, t);
}

PB_FN void pb_sb_f64(pb_sb *b, double v) {
    char t[40];
    snprintf(t, sizeof t, "%.17g", v);
    pb_sb_puts(b, t);
}

/* Bytes as a JSON string of hex digits. */
PB_FN void pb_sb_hex(pb_sb *b, const uint8_t *d, size_t n) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    pb_sb_put(b, "\"", 1);
    for (i = 0; i < n; i++) {
        char t[2];
        t[0] = digits[d[i] >> 4];
        t[1] = digits[d[i] & 15];
        pb_sb_put(b, t, 2);
    }
    pb_sb_put(b, "\"", 1);
}

/* A JSON string literal of n bytes of UTF-8. */
PB_FN void pb_sb_str(pb_sb *b, const char *s, size_t n) {
    size_t i;
    pb_sb_put(b, "\"", 1);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        char t[8];
        if (c == '"' || c == '\\') {
            t[0] = '\\';
            t[1] = (char)c;
            pb_sb_put(b, t, 2);
        } else if (c < 0x20) {
            snprintf(t, sizeof t, "\\u%04x", c);
            pb_sb_puts(b, t);
        } else {
            pb_sb_put(b, (const char *)&c, 1);
        }
    }
    pb_sb_put(b, "\"", 1);
}

/* The text, or NULL when out of memory (then nothing is left to free). */
PB_FN char *pb_sb_finish(pb_sb *b) {
    if (b->failed) {
        free(b->buf);
        return NULL;
    }
    if (!b->buf) {
        b->buf = (char *)malloc(1);
        if (b->buf) b->buf[0] = 0;
    }
    return b->buf;
}

/* Validate a decoded element count against the data that is left. */
PB_FN int pb_count(pb_reader *r, int64_t n, uint64_t elem_bits, size_t *out) {
    if (n < 0) return PB_ERR_INVALID;
    if (elem_bits > 0 && (uint64_t)n > pb_remaining_bits(r) / elem_bits) {
        uint64_t bits = (uint64_t)n * elem_bits;
        if (bits / elem_bits != (uint64_t)n || bits > (uint64_t)(size_t)-1) bits = (size_t)-1;
        return pb_short(r, (size_t)bits);
    }
    *out = (size_t)n;
    return PB_OK;
}

/* Allocate a zeroed array of n elements (never returns NULL for n == 0). */
PB_FN void *pb_alloc(size_t n, size_t size) { return calloc(n ? n : 1, size); }

/* Make room for `need` elements in *ptr (capacity *cap). */
PB_FN int pb_grow(void **ptr, size_t *cap, size_t need, size_t size) {
    if (need > *cap) {
        size_t ncap = *cap ? *cap * 2 : 8;
        void *p;
        while (ncap < need) ncap *= 2;
        p = realloc(*ptr, ncap * size);
        if (!p) return PB_ERR_NOMEM;
        memset((uint8_t *)p + *cap * size, 0, (ncap - *cap) * size);
        *ptr = p;
        *cap = ncap;
    }
    return PB_OK;
}

void pb_writer_init(pb_writer *w) { memset(w, 0, sizeof *w); }

void pb_writer_free(pb_writer *w) {
    size_t i;
    for (i = 0; i < w->nplaced; i++) free(w->placed[i].data);
    free(w->placed);
    free(w->buf);
    w->buf = NULL;
    w->placed = NULL;
    w->len = w->cap = w->pos = w->nplaced = w->capplaced = 0;
}

PB_FN int pb_writer_reserve(pb_writer *w, size_t extra) {
    if (w->len + extra > w->cap) {
        size_t ncap = w->cap ? w->cap * 2 : 64;
        uint8_t *p;
        while (ncap < w->len + extra) ncap *= 2;
        p = (uint8_t *)realloc(w->buf, ncap);
        if (!p) return PB_ERR_NOMEM;
        w->buf = p;
        w->cap = ncap;
    }
    return PB_OK;
}

PB_FN int pb_write_bits(pb_writer *w, uint64_t value, unsigned width) {
    unsigned left = width;
    PB_PASS(pb_writer_reserve(w, width / 8 + 2));
    while (left > 0) {
        unsigned off, take;
        if ((w->pos & 7) == 0) w->buf[w->len++] = 0;
        off = (unsigned)(w->pos & 7);
        take = 8 - off < left ? 8 - off : left;
        w->buf[w->len - 1] |= (uint8_t)(((value >> (left - take)) & ((1u << take) - 1u)) << (8 - off - take));
        w->pos += take;
        left -= take;
    }
    return PB_OK;
}

PB_FN int pb_write_uint(pb_writer *w, uint64_t value, unsigned nbytes, int little) {
    unsigned i;
    PB_PASS(pb_writer_reserve(w, nbytes));
    for (i = 0; i < nbytes; i++) {
        unsigned shift = little ? 8 * i : 8 * (nbytes - 1 - i);
        w->buf[w->len++] = (uint8_t)(value >> shift);
    }
    w->pos += (size_t)nbytes * 8;
    return PB_OK;
}

PB_FN int pb_write_bytes(pb_writer *w, const uint8_t *data, size_t n) {
    PB_PASS(pb_writer_reserve(w, n));
    if (n) memcpy(w->buf + w->len, data, n);
    w->len += n;
    w->pos += n * 8;
    return PB_OK;
}

PB_FN int pb_write_zero_bits(pb_writer *w, int64_t bits) {
    for (; bits > 32; bits -= 32) PB_PASS(pb_write_bits(w, 0, 32));
    if (bits > 0) PB_PASS(pb_write_bits(w, 0, (unsigned)bits));
    return PB_OK;
}

/* Start *s, a writer for a packet placed `offset` bytes after bit `from` of
 * w (the packet start), or after the start of the output (`root`). */
PB_FN int pb_writer_sub(pb_writer *w, pb_writer *s, size_t from, int64_t offset, int root) {
    size_t start = root ? 0 : w->base + from;
    pb_writer_init(s);
    s->tr = w->tr;
    if (offset < 0 || start % 8) return PB_ERR_RANGE;
    s->base = start + (size_t)offset * 8;
    return PB_OK;
}

/* Keep what s wrote (rc is how encoding into it went) for
 * pb_writer_finish, and release s. On failure w takes over s's error. */
PB_FN int pb_writer_place(pb_writer *w, pb_writer *s, int rc) {
    size_t need, i;
    if (rc == PB_OK) {
        need = w->nplaced + 1 + s->nplaced;
        if (need > w->capplaced) {
            size_t ncap = w->capplaced ? w->capplaced * 2 : 4;
            pb_placed *n;
            while (ncap < need) ncap *= 2;
            n = (pb_placed *)realloc(w->placed, ncap * sizeof *n);
            if (!n) rc = PB_ERR_NOMEM;
            else {
                w->placed = n;
                w->capplaced = ncap;
            }
        }
    }
    if (rc != PB_OK) {
        if (w->err.code == PB_OK && s->err.code != PB_OK) {
            w->err = s->err;
            w->tr = s->tr;
        }
        pb_writer_free(s);
        return rc;
    }
    w->placed[w->nplaced].at = s->base / 8;
    w->placed[w->nplaced].data = s->buf;
    w->placed[w->nplaced].len = s->len;
    w->placed[w->nplaced].tr = w->tr;
    w->nplaced++;
    for (i = 0; i < s->nplaced; i++) w->placed[w->nplaced++] = s->placed[i];
    free(s->placed);
    memset(s, 0, sizeof *s);
    return PB_OK;
}

int pb_writer_finish(pb_writer *w) {
    size_t i, j, k;
    /* Insertion sort by offset, keeping the order of equal offsets. */
    for (i = 1; i < w->nplaced; i++) {
        pb_placed x = w->placed[i];
        for (j = i; j > 0 && w->placed[j - 1].at > x.at; j--) w->placed[j] = w->placed[j - 1];
        w->placed[j] = x;
    }
    for (i = 0; i < w->nplaced; i++) {
        pb_placed *pl = &w->placed[i];
        /* The output reaches the offset even when the packet is empty. */
        if (w->len < pl->at) PB_PASS(pb_write_zero_bits(w, (int64_t)(pl->at - w->len) * 8));
        for (j = 0; j < pl->len; j++) {
            k = pl->at + j;
            if (k < w->len) {
                if (w->buf[k] != pl->data[j]) {
                    w->tr = pl->tr;
                    return pb_note(&w->tr, &w->err, PB_ERR_MISMATCH, k * 8, 0);
                }
            } else {
                if (k > w->len) PB_PASS(pb_write_zero_bits(w, (int64_t)(k - w->len) * 8));
                PB_PASS(pb_write_bytes(w, pl->data + j, 1));
            }
        }
    }
    for (i = 0; i < w->nplaced; i++) free(w->placed[i].data);
    free(w->placed);
    w->placed = NULL;
    w->nplaced = w->capplaced = 0;
    return PB_OK;
}

/* End a window of `size` bytes that started at bit `start`: the content
 * must fit (and fill it when `exact`); the rest is zero-filled. */
PB_FN int pb_end_window(pb_writer *w, size_t start, int64_t size, int exact) {
    size_t used = w->pos - start;
    size_t room = size < 0 ? 0 : (size_t)size * 8;
    if (size < 0 || used > room) return PB_ERR_RANGE;
    if (exact && used != room) return PB_ERR_MISMATCH;
    return pb_write_zero_bits(w, (int64_t)(room - used));
}

/* Overwrite nbytes bytes at bit position `at` (byte aligned). */
PB_FN void pb_patch_uint(pb_writer *w, size_t at, uint64_t value, unsigned nbytes, int little) {
    unsigned i;
    for (i = 0; i < nbytes; i++) {
        unsigned shift = little ? 8 * i : 8 * (nbytes - 1 - i);
        w->buf[at / 8 + i] = (uint8_t)(value >> shift);
    }
}

/* Overwrite `width` bits at bit position `at`, MSB first. */
PB_FN void pb_patch_bits(pb_writer *w, size_t at, uint64_t value, unsigned width) {
    unsigned i;
    for (i = 0; i < width; i++) {
        unsigned bit = (unsigned)((value >> (width - 1 - i)) & 1u);
        size_t byte = (at + i) / 8;
        unsigned off = 7 - (unsigned)((at + i) % 8);
        w->buf[byte] = (uint8_t)((w->buf[byte] & ~(1u << off)) | (bit << off));
    }
}

/* Checksum `algo` of buf[from..to), with buf[hole_from..hole_to) as zeros.
 * 0-7: CRCs (crc8, crc16_arc, crc16_ccitt_false, crc16_xmodem, crc16_kermit,
 * crc16_modbus, crc32, crc32c), 8: Internet checksum (RFC 1071),
 * 9: Fletcher-16, 10: sum8, 11: xor8. */
PB_FN uint64_t pb_checksum(unsigned algo, const uint8_t *buf, size_t from, size_t to, size_t hole_from, size_t hole_to) {
    size_t i;
    uint64_t a = 0, b = 0;
    for (i = from; i < to; i++) {
        uint64_t x = (i >= hole_from && i < hole_to) ? 0 : buf[i];
        switch (algo) {
        case 8: a += (i - from) % 2 == 0 ? x << 8 : x; break;
        case 9: a = (a + x) % 255; b = (b + a) % 255; break;
        case 10: a = (a + x) & 0xff; break;
        case 11: a ^= x; break;
        default: break;
        }
    }
    if (algo == 8) {
        while (a >> 16) a = (a & 0xffff) + (a >> 16);
        return ~a & 0xffff;
    }
    if (algo == 9) return (b << 8) | a;
    if (algo >= 10) return a;
    {
        unsigned width = 16;
        uint64_t poly = 0x1021, init = 0, xorout = 0, crc, mask;
        int reflected = 0;
        unsigned k;
        switch (algo) {
        case 0: width = 8; poly = 0x07; break;
        case 1: poly = 0xa001; reflected = 1; break;
        case 2: init = 0xffff; break;
        case 3: break;
        case 4: poly = 0x8408; reflected = 1; break;
        case 5: poly = 0xa001; init = 0xffff; reflected = 1; break;
        case 6: width = 32; poly = 0xedb88320u; init = xorout = 0xffffffffu; reflected = 1; break;
        default: width = 32; poly = 0x82f63b78u; init = xorout = 0xffffffffu; reflected = 1; break;
        }
        mask = (((uint64_t)1) << width) - 1;
        crc = init;
        for (i = from; i < to; i++) {
            uint64_t x = (i >= hole_from && i < hole_to) ? 0 : buf[i];
            if (reflected) {
                crc ^= x;
                for (k = 0; k < 8; k++) crc = (crc & 1) ? (crc >> 1) ^ poly : crc >> 1;
            } else {
                crc ^= x << (width - 8);
                for (k = 0; k < 8; k++) crc = ((crc & ((uint64_t)1 << (width - 1))) ? (crc << 1) ^ poly : crc << 1) & mask;
            }
        }
        return (crc ^ xorout) & mask;
    }
}

/* Checksum of the input or output between two bit positions (whole bytes). */
PB_FN uint64_t pb_reader_checksum(const pb_reader *r, unsigned algo, size_t from, size_t to, size_t hole_from, size_t hole_to) {
    return pb_checksum(algo, r->data, from / 8, to / 8, hole_from / 8, hole_to / 8);
}

PB_FN uint64_t pb_writer_checksum(const pb_writer *w, unsigned algo, size_t from, size_t to, size_t hole_from, size_t hole_to) {
    return pb_checksum(algo, w->buf, from / 8, to / 8, hole_from / 8, hole_to / 8);
}

/* One variable-length integer (see pb_read_varint). */
PB_FN int pb_write_varint(pb_writer *w, unsigned kind, uint64_t v) {
    if (kind == 5) {
        if (v > 0x7fff) return PB_ERR_RANGE;
        return v < 0x80 ? pb_write_uint(w, v, 1, 0) : pb_write_uint(w, v | 0x8000, 2, 0);
    }
    if (kind == 4) {
        unsigned n = v <= 0x3f ? 1 : v <= 0x3fff ? 2 : v <= 0x3fffffffu ? 4 : 8, code = n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3;
        if (v > 0x3fffffffffffffffULL) return PB_ERR_RANGE;
        return pb_write_uint(w, v | ((uint64_t)code << (8 * n - 2)), n, 0);
    }
    if (kind == 1) {
        int64_t x = (int64_t)v;
        for (;;) {
            uint64_t b = (uint64_t)x & 0x7f;
            int done;
            x = x < 0 ? (int64_t)~(~(uint64_t)x >> 7) : (int64_t)((uint64_t)x >> 7);
            done = (x == 0 && !(b & 0x40)) || (x == -1 && (b & 0x40));
            PB_PASS(pb_write_uint(w, done ? b : b | 0x80, 1, 0));
            if (done) return PB_OK;
        }
    }
    if (kind == 3) {
        uint8_t g[10];
        int k = 0;
        g[k++] = (uint8_t)(v & 0x7f);
        for (v >>= 7; v; v >>= 7) g[k++] = (uint8_t)((v & 0x7f) | 0x80);
        while (k > 0) PB_PASS(pb_write_uint(w, g[--k], 1, 0));
        return PB_OK;
    }
    if (kind == 2) v = (v << 1) ^ (0 - (v >> 63));
    do {
        uint64_t b = v & 0x7f;
        v >>= 7;
        PB_PASS(pb_write_uint(w, v ? b | 0x80 : b, 1, 0));
    } while (v);
    return PB_OK;
}

/* Decode one UTF-8 code point at s[*i] (the text is validated first). */
static uint32_t pb_next_utf8(const uint8_t *s, size_t *i) {
    uint8_t c = s[*i];
    uint32_t cp;
    size_t len, k;
    if (c < 0x80) { (*i)++; return c; }
    len = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : 2;
    cp = c & (len == 2 ? 0x1F : len == 3 ? 0x0F : 0x07);
    for (k = 1; k < len; k++) cp = (cp << 6) | (s[*i + k] & 0x3F);
    *i += len;
    return cp;
}

/* The size in bytes of UTF-8 text `s` in encoding `enc`; an error if a
 * character has no encoding there. */
PB_FN int pb_text_size(const char *s, size_t len, unsigned enc, size_t *size) {
    size_t i = 0, n = 0;
    if (len && !s) return PB_ERR_TEXT;
    if (!pb_utf8_valid((const uint8_t *)s, len)) return PB_ERR_TEXT;
    if (enc == 0) { *size = len; return PB_OK; }
    while (i < len) {
        uint32_t cp = pb_next_utf8((const uint8_t *)s, &i);
        if (enc == 1 && cp > 0x7f) return PB_ERR_TEXT;
        if (enc == 2 && cp > 0xff) return PB_ERR_TEXT;
        n += enc <= 2 ? 1 : cp >= 0x10000 ? 4 : 2;
    }
    *size = n;
    return PB_OK;
}

/* Write UTF-8 text `s` in encoding `enc` (validated by pb_text_size). */
PB_FN int pb_write_text(pb_writer *w, const char *s, size_t len, unsigned enc) {
    size_t i = 0;
    if (enc == 0) return pb_write_bytes(w, (const uint8_t *)s, len);
    while (i < len) {
        uint32_t cp = pb_next_utf8((const uint8_t *)s, &i);
        if (enc <= 2) {
            PB_PASS(pb_write_uint(w, cp, 1, 0));
        } else if (cp >= 0x10000) {
            cp -= 0x10000;
            PB_PASS(pb_write_uint(w, 0xD800 + (cp >> 10), 2, enc == 3));
            PB_PASS(pb_write_uint(w, 0xDC00 + (cp & 0x3FF), 2, enc == 3));
        } else {
            PB_PASS(pb_write_uint(w, cp, 2, enc == 3));
        }
    }
    return PB_OK;
}

/* The bytes written since bit `from` must not contain the terminator. */
PB_FN int pb_check_no_term(const pb_writer *w, size_t from, const uint8_t *term, size_t tlen) {
    size_t i, end = w->pos >> 3;
    for (i = from >> 3; i + tlen <= end; i++) {
        if (memcmp(w->buf + i, term, tlen) == 0) return PB_ERR_INVALID;
    }
    return PB_OK;
}

PB_FN int pb_check_fits(size_t len, int64_t size) {
    return (size < 0 || (uint64_t)len > (uint64_t)size) ? PB_ERR_RANGE : PB_OK;
}

PB_FN int pb_check_text(const char *s, size_t len, int allow_nul) {
    if (len && !s) return PB_ERR_TEXT;
    if (!allow_nul && len && memchr(s, 0, len)) return PB_ERR_TEXT;
    return pb_utf8_valid((const uint8_t *)s, len) ? PB_OK : PB_ERR_TEXT;
}

PB_FN int pb_check_len(size_t actual, int64_t expected) {
    return (expected < 0 || (uint64_t)actual != (uint64_t)expected) ? PB_ERR_MISMATCH : PB_OK;
}

PB_FN int pb_check_u(uint64_t v, unsigned width) {
    return (width < 64 && (v >> width) != 0) ? PB_ERR_RANGE : PB_OK;
}

PB_FN int pb_check_i(int64_t v, unsigned width) {
    if (width < 64) {
        int64_t lo = -(int64_t)((uint64_t)1 << (width - 1));
        int64_t hi = (int64_t)(((uint64_t)1 << (width - 1)) - 1);
        if (v < lo || v > hi) return PB_ERR_RANGE;
    }
    return PB_OK;
}

PB_FN int64_t pb_sext(uint64_t v, unsigned width) {
    if (width < 64 && ((v >> (width - 1)) & 1u)) v |= ~(uint64_t)0 << width;
    return (int64_t)v;
}

PB_FN int64_t pb_trunc(int64_t v, unsigned width, int is_signed) {
    uint64_t u;
    if (width >= 64) return v;
    u = (uint64_t)v & (((uint64_t)1 << width) - 1);
    return is_signed ? pb_sext(u, width) : (int64_t)u;
}

/* 64-bit two's complement arithmetic without signed overflow. */
PB_FN int64_t pb_add(int64_t a, int64_t b) { return (int64_t)((uint64_t)a + (uint64_t)b); }
PB_FN int64_t pb_sub(int64_t a, int64_t b) { return (int64_t)((uint64_t)a - (uint64_t)b); }
PB_FN int64_t pb_mul(int64_t a, int64_t b) { return (int64_t)((uint64_t)a * (uint64_t)b); }
PB_FN int64_t pb_div(int64_t a, int64_t b) {
    if (b == 0) return 0;
    if (b == -1) return pb_sub(0, a);
    return a / b;
}
PB_FN int64_t pb_mod(int64_t a, int64_t b) {
    if (b == 0 || b == -1) return 0;
    return a % b;
}

PB_FN int64_t pb_shl(int64_t a, int64_t b) {
    if (b < 0 || b > 63) return 0;
    return (int64_t)((uint64_t)a << b);
}

PB_FN int64_t pb_shr(int64_t a, int64_t b) {
    if (b < 0) return 0;
    if (b > 63) b = 63;
    /* arithmetic shift without relying on implementation-defined >> */
    return a < 0 ? (int64_t)~(~(uint64_t)a >> b) : (int64_t)((uint64_t)a >> b);
}

PB_FN int64_t pb_neg(int64_t a) { return (int64_t)(0 - (uint64_t)a); }

PB_FN int64_t pb_pow(int64_t base, int64_t exp) {
    uint64_t acc = 1, b = (uint64_t)base, e;
    if (exp < 0) return 0;
    for (e = (uint64_t)exp; e > 0; e >>= 1) {
        if (e & 1u) acc *= b;
        b *= b;
    }
    return (int64_t)acc;
}
PB_FN int64_t pb_min_i(int64_t a, int64_t b) { return b < a ? b : a; }
PB_FN int64_t pb_max_i(int64_t a, int64_t b) { return b > a ? b : a; }
PB_FN double pb_min_f(double a, double b) { return b < a ? b : a; }
PB_FN double pb_max_f(double a, double b) { return b > a ? b : a; }
PB_FN int64_t pb_ftoi(double v) {
    if (v != v) return 0;
    if (v >= 9223372036854775807.0) return INT64_MAX;
    if (v <= -9223372036854775808.0) return INT64_MIN;
    return (int64_t)v;
}
PB_FN float pb_f32_from_bits(uint64_t bits) {
    uint32_t b = (uint32_t)bits;
    float f;
    memcpy(&f, &b, 4);
    return f;
}
PB_FN double pb_f64_from_bits(uint64_t bits) {
    double f;
    memcpy(&f, &bits, 8);
    return f;
}
PB_FN uint64_t pb_f32_bits(float f) {
    uint32_t b;
    memcpy(&b, &f, 4);
    return b;
}
PB_FN uint64_t pb_f64_bits(double f) {
    uint64_t b;
    memcpy(&b, &f, 8);
    return b;
}

/* Array helpers: element access (0 when out of range) and aggregates. */
#define PB_ARRAY_HELPERS(T, NAME)                                                   \
    PB_FN T pb_at_##NAME(const T *a, size_t n, int64_t i) {                        \
        return (i >= 0 && (uint64_t)i < (uint64_t)n) ? a[i] : (T)0;                 \
    }                                                                               \
    PB_FN int64_t pb_sum_##NAME(const T *a, size_t n) {                            \
        int64_t acc = 0; size_t i;                                                  \
        for (i = 0; i < n; i++) acc = pb_add(acc, (int64_t)a[i]);                   \
        return acc;                                                                 \
    }                                                                               \
    PB_FN int64_t pb_prod_##NAME(const T *a, size_t n) {                           \
        int64_t acc = 1; size_t i;                                                  \
        for (i = 0; i < n; i++) acc = pb_mul(acc, (int64_t)a[i]);                   \
        return acc;                                                                 \
    }                                                                               \
    PB_FN double pb_sumf_##NAME(const T *a, size_t n) {                            \
        double acc = 0; size_t i;                                                   \
        for (i = 0; i < n; i++) acc += (double)a[i];                                \
        return acc;                                                                 \
    }                                                                               \
    PB_FN double pb_prodf_##NAME(const T *a, size_t n) {                           \
        double acc = 1; size_t i;                                                   \
        for (i = 0; i < n; i++) acc *= (double)a[i];                                \
        return acc;                                                                 \
    }

PB_ARRAY_HELPERS(uint8_t, u8)
PB_ARRAY_HELPERS(int8_t, i8)
PB_ARRAY_HELPERS(uint16_t, u16)
PB_ARRAY_HELPERS(int16_t, i16)
PB_ARRAY_HELPERS(uint32_t, u32)
PB_ARRAY_HELPERS(int32_t, i32)
PB_ARRAY_HELPERS(uint64_t, u64)
PB_ARRAY_HELPERS(int64_t, i64)
PB_ARRAY_HELPERS(float, f32)
PB_ARRAY_HELPERS(double, f64)

#endif /* PB_RUNTIME_IMPLEMENTED */
